using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Demiurge.Core.Intel;
using Demiurge.Core.Model;
using Demiurge.Core.Storage;

namespace Demiurge.Core.Enrichment;

/// <summary>
/// Reputación por hash (nunca se suben archivos): feeds locales, CIRCL hashlookup (allowlist, TI-05),
/// MalwareBazaar (TI-04) y VirusTotal opcional con API key del usuario (TI-08). Caché con TTL en SQLite
/// y rate limiting por fuente.
/// </summary>
public sealed class ReputationService
{
    private readonly HttpClient _http;
    private readonly DemiurgeDb _db;
    private readonly FeedStore _feeds;
    private readonly DemiurgeOptions _options;
    private readonly ILogger _logger;

    private readonly SemaphoreSlim _circlGate = new(4);
    private readonly SemaphoreSlim _bazaarGate = new(2);
    // VirusTotal API pública: 4 requests/minuto.
    private readonly SemaphoreSlim _vtGate = new(1);
    private DateTimeOffset _vtNext = DateTimeOffset.MinValue;
    private bool _bazaarDisabled;

    public ReputationService(HttpClient http, DemiurgeDb db, FeedStore feeds, DemiurgeOptions options, ILogger logger)
    {
        _http = http;
        _db = db;
        _feeds = feeds;
        _options = options;
        _logger = logger;
    }

    private TimeSpan Ttl => TimeSpan.FromHours(_options.ReputationTtlHours);

    /// <summary>Enriquece todos los binarios del snapshot. Online sólo para los que hace falta.</summary>
    public async Task EnrichAsync(ScanSnapshot snapshot, CancellationToken ct)
    {
        var bins = snapshot.Binaries.Values.Where(b => b.Sha256 is not null).ToList();

        // 1) Feeds locales: siempre.
        foreach (var b in bins)
        {
            var hit = _feeds.MatchHash(b.Sha256, b.Sha1, b.Md5);
            if (hit is not null)
                b.Reputation.Add(new ReputationInfo { Source = hit.Source, Verdict = "malicious", Family = hit.Family, Fetched = DateTimeOffset.Now });
        }

        if (!_options.OnlineHashLookups) return;

        // 2) CIRCL hashlookup (allowlist): binarios que no firma Microsoft.
        var needCircl = bins.Where(b => b.Signature?.IsMicrosoft != true && b.Malicious is null).ToList();
        await Task.WhenAll(needCircl.Select(b => WithCache(b, "CIRCL", _circlGate, () => QueryCirclAsync(b.Sha256!, ct), ct))).ConfigureAwait(false);

        // 3) MalwareBazaar: binarios sin firma válida y no conocidos como benignos.
        var needBazaar = bins.Where(b => b.Signature?.IsValid != true && !b.IsKnownGood && b.Malicious is null).ToList();
        await Task.WhenAll(needBazaar.Select(b => WithCache(b, "MalwareBazaar", _bazaarGate, () => QueryBazaarAsync(b.Sha256!, ct), ct))).ConfigureAwait(false);

        // 4) VirusTotal: opcional; mismo criterio, con límite para no agotar la cuota.
        if (!string.IsNullOrEmpty(_options.VirusTotalApiKey))
        {
            foreach (var b in needBazaar.Where(b => !b.IsKnownGood && b.Malicious is null).Take(16))
                await WithCache(b, "VirusTotal", _vtGate, () => QueryVirusTotalAsync(b.Sha256!, ct), ct).ConfigureAwait(false);
        }
    }

    private async Task WithCache(BinaryInfo b, string source, SemaphoreSlim gate, Func<Task<ReputationInfo?>> query, CancellationToken ct)
    {
        var cached = _db.GetReputation(b.Sha256!, source, Ttl);
        if (cached is null)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try { cached = await query().ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug("{Source} {Hash}: {Error}", source, b.Sha256, ex.Message);
                cached = null;
            }
            finally { gate.Release(); }
            if (cached is not null) _db.PutReputation(b.Sha256!, cached);
        }
        if (cached is not null && cached.Verdict != "unknown")
            lock (b.Reputation) b.Reputation.Add(cached);
    }

    private async Task<ReputationInfo?> QueryCirclAsync(string sha256, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"https://hashlookup.circl.lu/lookup/sha256/{sha256}");
        req.Headers.Accept.ParseAdd("application/json");
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.NotFound)
            return new ReputationInfo { Source = "CIRCL", Verdict = "unknown", Fetched = DateTimeOffset.Now };
        if (!resp.IsSuccessStatusCode) return null;
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        string? product = doc.RootElement.TryGetProperty("ProductName", out var pn) ? pn.GetString() : null;
        return new ReputationInfo { Source = "CIRCL", Verdict = "benign", Family = product, Fetched = DateTimeOffset.Now };
    }

    private async Task<ReputationInfo?> QueryBazaarAsync(string sha256, CancellationToken ct)
    {
        if (_bazaarDisabled) return null;
        using var req = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["query"] = "get_info", ["hash"] = sha256 }),
        };
        if (!string.IsNullOrEmpty(_options.AbuseChAuthKey)) req.Headers.Add("Auth-Key", _options.AbuseChAuthKey);
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            _bazaarDisabled = true;
            _logger.LogWarning("MalwareBazaar requiere Auth-Key (configurar AbuseChAuthKey). Consultas deshabilitadas en este escaneo.");
            return null;
        }
        if (!resp.IsSuccessStatusCode) return null;
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        var status = doc.RootElement.GetProperty("query_status").GetString();
        if (status == "ok" && doc.RootElement.TryGetProperty("data", out var data) && data.GetArrayLength() > 0)
        {
            var first = data[0];
            var sig = first.TryGetProperty("signature", out var s) ? s.GetString() : null;
            return new ReputationInfo { Source = "MalwareBazaar", Verdict = "malicious", Family = sig, Fetched = DateTimeOffset.Now };
        }
        return status is "hash_not_found" or "no_results"
            ? new ReputationInfo { Source = "MalwareBazaar", Verdict = "unknown", Fetched = DateTimeOffset.Now }
            : null;
    }

    private async Task<ReputationInfo?> QueryVirusTotalAsync(string sha256, CancellationToken ct)
    {
        var wait = _vtNext - DateTimeOffset.Now;
        if (wait > TimeSpan.Zero) await Task.Delay(wait, ct).ConfigureAwait(false);
        _vtNext = DateTimeOffset.Now.AddSeconds(15);

        using var req = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
        req.Headers.Add("x-apikey", _options.VirusTotalApiKey);
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.NotFound)
            return new ReputationInfo { Source = "VirusTotal", Verdict = "unknown", Fetched = DateTimeOffset.Now };
        if (!resp.IsSuccessStatusCode) return null;
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        var attrs = doc.RootElement.GetProperty("data").GetProperty("attributes");
        int malicious = attrs.GetProperty("last_analysis_stats").GetProperty("malicious").GetInt32();
        string? label = attrs.TryGetProperty("popular_threat_classification", out var ptc) &&
                        ptc.TryGetProperty("suggested_threat_label", out var l) ? l.GetString() : null;
        // "clean" no entra en la allowlist dura (sólo CIRCL/NSRL da "benign"): un malware nuevo puede tener 0 detecciones.
        string verdict = malicious >= _options.VirusTotalMinDetections ? "malicious" : malicious == 0 ? "clean" : "unknown";
        return new ReputationInfo { Source = "VirusTotal", Verdict = verdict, Family = label, Detections = malicious, Fetched = DateTimeOffset.Now };
    }
}
