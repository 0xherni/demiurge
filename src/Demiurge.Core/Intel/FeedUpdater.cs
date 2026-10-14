using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Demiurge.Core.Util;

namespace Demiurge.Core.Intel;

/// <summary>
/// Descarga y actualiza feeds (04_Inteligencia). Verifica integridad parseando el archivo antes
/// de reemplazar el anterior; si falla, sigue funcionando offline con la última copia.
/// </summary>
public sealed class FeedUpdater
{
    private sealed record Feed(string Id, string File, string Url, TimeSpan Every, Action<string> Validate, bool NeedsAuthKey = false);

    private readonly HttpClient _http;
    private readonly ILogger _logger;
    private readonly DemiurgeOptions _options;

    public FeedUpdater(HttpClient http, DemiurgeOptions options, ILogger logger)
    {
        _http = http;
        _options = options;
        _logger = logger;
    }

    private IEnumerable<Feed> Feeds()
    {
        var sixHours = TimeSpan.FromHours(Math.Max(1, _options.FeedUpdateHours));
        yield return new Feed("TI-01", FeedNames.ThreatFox, "https://threatfox.abuse.ch/export/csv/recent/", sixHours,
            p => { var d = new Dictionary<string, IocInfo>(); FeedStore.LoadThreatFox(p, d, d, d, d); if (d.Count == 0) throw new InvalidDataException("vacío"); });
        yield return new Feed("TI-02", FeedNames.Urlhaus, "https://urlhaus.abuse.ch/downloads/csv_online/", sixHours,
            p => { var d = new Dictionary<string, IocInfo>(); FeedStore.LoadUrlhaus(p, d); if (d.Count == 0) throw new InvalidDataException("vacío"); });
        yield return new Feed("TI-03", FeedNames.Feodo, "https://feodotracker.abuse.ch/downloads/ipblocklist.json", sixHours,
            p => { var d = new Dictionary<string, IocInfo>(); FeedStore.LoadFeodo(p, d, d); });
        yield return new Feed("TI-06", FeedNames.Lolbas, "https://lolbas-project.github.io/api/lolbas.json", TimeSpan.FromDays(7),
            p => { if (FeedStore.LoadLolbas(p).Count < 50) throw new InvalidDataException("muy pocas entradas"); });
        yield return new Feed("TI-07", FeedNames.LolDrivers, "https://www.loldrivers.io/api/drivers.json", TimeSpan.FromDays(7),
            p => { if (FeedStore.LoadLolDrivers(p).Count < 50) throw new InvalidDataException("muy pocas entradas"); });
    }

    /// <summary>Actualiza los feeds vencidos. Devuelve true si cambió alguno.</summary>
    public async Task<bool> UpdateAsync(bool force, CancellationToken ct)
    {
        bool changed = false;
        foreach (var feed in Feeds())
        {
            ct.ThrowIfCancellationRequested();
            var target = FeedStore.FilePath(feed.File);
            if (!force && File.Exists(target) && DateTime.UtcNow - File.GetLastWriteTimeUtc(target) < feed.Every) continue;
            changed |= await DownloadAsync(feed, target, ct).ConfigureAwait(false);
        }

        // TI-13: lista de raíces de Microsoft (mensual).
        var authroot = FeedStore.FilePath(FeedNames.AuthRoot);
        if (force || !File.Exists(authroot) || DateTime.UtcNow - File.GetLastWriteTimeUtc(authroot) > TimeSpan.FromDays(30))
            changed |= await UpdateAuthRootAsync(authroot, ct).ConfigureAwait(false);

        return changed;
    }

    private async Task<bool> DownloadAsync(Feed feed, string target, CancellationToken ct)
    {
        var tmp = target + ".download";
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, feed.Url);
            if (!string.IsNullOrEmpty(_options.AbuseChAuthKey) && feed.Url.Contains("abuse.ch", StringComparison.OrdinalIgnoreCase))
                req.Headers.Add("Auth-Key", _options.AbuseChAuthKey);
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            await using (var fs = File.Create(tmp))
                await resp.Content.CopyToAsync(fs, ct).ConfigureAwait(false);

            feed.Validate(tmp);
            File.Move(tmp, target, overwrite: true);
            _logger.LogInformation("Feed {Feed} actualizado", feed.Id);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning("No se pudo actualizar {Feed} ({Url}): {Error}. Se usa la copia anterior.", feed.Id, feed.Url, ex.Message);
            try { File.Delete(tmp); } catch { }
            return false;
        }
    }

    private async Task<bool> UpdateAuthRootAsync(string target, CancellationToken ct)
    {
        const string url = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";
        var work = DemiurgePaths.Ensure(Path.Combine(DemiurgePaths.Feeds, "authroot_tmp"));
        try
        {
            var cab = Path.Combine(work, "authrootstl.cab");
            await using (var fs = File.Create(cab))
                await (await _http.GetStreamAsync(url, ct).ConfigureAwait(false)).CopyToAsync(fs, ct).ConfigureAwait(false);

            // expand.exe a veces nombra la salida como el CAB: extraemos a una carpeta propia y tomamos lo que salga.
            var outDir = DemiurgePaths.Ensure(Path.Combine(work, "out"));
            var expand = Path.Combine(PathClassifier.System32Dir, "expand.exe");
            var psi = new ProcessStartInfo(expand, $"\"{cab}\" -F:* \"{outDir}\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
            using (var p = Process.Start(psi)!)
            {
                await p.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
                await p.WaitForExitAsync(ct).ConfigureAwait(false);
            }
            var stl = Directory.EnumerateFiles(outDir).OrderByDescending(f => new FileInfo(f).Length).FirstOrDefault()
                      ?? throw new InvalidDataException("No se pudo extraer authroot.stl del CAB");

            // El CAB no está firmado: la firma de Microsoft está en la CTL (PKCS#7) de adentro. Verificamos antes de usarla.
            FeedStore.VerifyAuthRootSignature(stl);
            if (FeedStore.LoadAuthRoot(stl).Count < 100) throw new InvalidDataException("authroot.stl con muy pocas raíces");
            File.Move(stl, target, overwrite: true);
            _logger.LogInformation("Lista authroot (TI-13) actualizada");
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning("No se pudo actualizar authroot: {Error}", ex.Message);
            return false;
        }
        finally
        {
            try { Directory.Delete(work, true); } catch { }
        }
    }
}
