using System.Formats.Asn1;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography.Pkcs;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Demiurge.Core.Util;

namespace Demiurge.Core.Intel;

public sealed record IocInfo(string Source, string Category, string? Family, string? Reference);

/// <summary>
/// Feeds de inteligencia descargados y matcheados localmente (principio de privacidad).
/// Carga los archivos crudos de %ProgramData%\Demiurge\feeds y los indexa en memoria.
/// </summary>
public sealed class FeedStore
{
    private readonly ILogger _logger;

    public FeedStore(ILogger logger) => _logger = logger;

    public Dictionary<string, IocInfo> Ips { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, IocInfo> IpPorts { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, IocInfo> Domains { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, IocInfo> Hashes { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>URLs completas (URLhaus / ThreatFox): para hostings compartidos se matchea la URL exacta, no el dominio.</summary>
    public Dictionary<string, IocInfo> Urls { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>LOLBAS: nombre de binario → categorías de abuso documentadas.</summary>
    public Dictionary<string, HashSet<string>> Lolbas { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, IocInfo> LolDrivers { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> AuthRootThumbprints { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

    public string Version { get; private set; } = "sin feeds";
    public DateTimeOffset? LastLoaded { get; private set; }

    public static string FilePath(string name) => Path.Combine(DemiurgePaths.Feeds, name);

    public void Load()
    {
        var ips = new Dictionary<string, IocInfo>(StringComparer.OrdinalIgnoreCase);
        var ipPorts = new Dictionary<string, IocInfo>(StringComparer.OrdinalIgnoreCase);
        var domains = new Dictionary<string, IocInfo>(StringComparer.OrdinalIgnoreCase);
        var hashes = new Dictionary<string, IocInfo>(StringComparer.OrdinalIgnoreCase);
        var urls = new Dictionary<string, IocInfo>(StringComparer.OrdinalIgnoreCase);

        Try("threatfox", () => LoadThreatFox(FilePath(FeedNames.ThreatFox), ips, ipPorts, domains, hashes, urls));
        Try("urlhaus", () => LoadUrlhaus(FilePath(FeedNames.Urlhaus), domains, urls));
        Try("feodo", () => LoadFeodo(FilePath(FeedNames.Feodo), ips, ipPorts));
        Try("lolbas", () => Lolbas = LoadLolbas(FilePath(FeedNames.Lolbas)));
        Try("loldrivers", () => LolDrivers = LoadLolDrivers(FilePath(FeedNames.LolDrivers)));
        Try("authroot", () => AuthRootThumbprints = LoadAuthRoot(FilePath(FeedNames.AuthRoot)));

        Ips = ips;
        IpPorts = ipPorts;
        Domains = domains;
        Hashes = hashes;
        Urls = urls;
        LastLoaded = DateTimeOffset.Now;

        var stamps = new[] { FeedNames.ThreatFox, FeedNames.Urlhaus, FeedNames.Feodo }
            .Select(FilePath).Where(File.Exists).Select(File.GetLastWriteTimeUtc).ToList();
        Version = stamps.Count == 0 ? "sin feeds" : stamps.Max().ToString("yyyyMMdd-HHmm") + $" ({ips.Count + domains.Count + hashes.Count} IOCs)";
        _logger.LogInformation("Feeds cargados: {Ips} IPs, {Domains} dominios, {Hashes} hashes, {Lolbas} LOLBAS, {Drivers} LOLDrivers, {Roots} raíces",
            ips.Count, domains.Count, hashes.Count, Lolbas.Count, LolDrivers.Count, AuthRootThumbprints.Count);
    }

    private void Try(string name, Action a)
    {
        try { a(); }
        catch (FileNotFoundException) { }
        catch (Exception ex) { _logger.LogWarning(ex, "No se pudo cargar el feed {Feed}", name); }
    }

    // ---------------- Matching ----------------

    public IocInfo? MatchIp(string? ip, int port)
    {
        if (string.IsNullOrEmpty(ip)) return null;
        if (IpPorts.TryGetValue($"{ip}:{port}", out var hit)) return hit;
        return Ips.TryGetValue(ip, out hit) ? hit : null;
    }

    /// <summary>Matchea el dominio y sus padres (a.b.evil.com → evil.com), sin llegar al TLD.</summary>
    public IocInfo? MatchDomain(string? domain)
    {
        if (string.IsNullOrEmpty(domain)) return null;
        var d = domain.TrimEnd('.').ToLowerInvariant();
        while (d.Count(c => c == '.') >= 1)
        {
            if (Domains.TryGetValue(d, out var hit)) return hit;
            int i = d.IndexOf('.');
            d = d[(i + 1)..];
        }
        return null;
    }

    public IocInfo? MatchUrl(string? url) =>
        url is not null && Urls.TryGetValue(url.Trim(), out var hit) ? hit : null;

    public IocInfo? MatchHash(params string?[] hashes)
    {
        foreach (var h in hashes)
            if (h is not null && Hashes.TryGetValue(h, out var hit)) return hit;
        return null;
    }

    // ---------------- Parsers ----------------

    internal static IEnumerable<string> ReadLines(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException(path);
        var bytes = File.ReadAllBytes(path);
        Stream s = new MemoryStream(bytes);
        if (bytes.Length > 4 && bytes[0] == 'P' && bytes[1] == 'K')
        {
            var zip = new ZipArchive(s);
            s = zip.Entries.OrderByDescending(e => e.Length).First().Open();
        }
        using var sr = new StreamReader(s);
        string? line;
        while ((line = sr.ReadLine()) is not null) yield return line;
    }

    internal static List<string> SplitCsv(string line)
    {
        var result = new List<string>();
        var cur = new System.Text.StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '"')
            {
                if (quoted && i + 1 < line.Length && line[i + 1] == '"') { cur.Append('"'); i++; }
                else quoted = !quoted;
            }
            else if (c == ',' && !quoted) { result.Add(cur.ToString().Trim()); cur.Clear(); }
            else cur.Append(c);
        }
        result.Add(cur.ToString().Trim());
        return result;
    }

    /// <summary>ThreatFox CSV: first_seen, ioc_id, ioc_value, ioc_type, threat_type, fk_malware, malware_alias, malware_printable, ...</summary>
    internal static void LoadThreatFox(string path, Dictionary<string, IocInfo> ips, Dictionary<string, IocInfo> ipPorts,
        Dictionary<string, IocInfo> domains, Dictionary<string, IocInfo> hashes, Dictionary<string, IocInfo>? urls = null)
    {
        foreach (var line in ReadLines(path))
        {
            if (line.StartsWith('#') || line.Length == 0) continue;
            var f = SplitCsv(line);
            if (f.Count < 8) continue;
            var value = f[2];
            var type = f[3];
            var info = new IocInfo("ThreatFox", ThreatTypeEs(f[4]), NullIfNone(f[7]), f.Count > 10 ? NullIfNone(f[10]) : null);
            switch (type)
            {
                case "ip:port":
                    ipPorts.TryAdd(value, info);
                    var ip = value[..value.LastIndexOf(':')];
                    ips.TryAdd(ip.Trim('[', ']'), info);
                    break;
                case "domain":
                    domains.TryAdd(value.ToLowerInvariant(), info);
                    break;
                case "url":
                    urls?.TryAdd(value, info);
                    if (!Uri.TryCreate(value, UriKind.Absolute, out var u)) break;
                    if (IPAddress.TryParse(u.Host, out _)) ips.TryAdd(u.Host, info);
                    else if (!IsSharedHost(u.Host)) domains.TryAdd(u.Host.ToLowerInvariant(), info);
                    break;
                case "md5_hash" or "sha1_hash" or "sha256_hash":
                    hashes.TryAdd(value.ToLowerInvariant(), info);
                    break;
            }
        }
    }

    /// <summary>URLhaus CSV: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter.</summary>
    internal static void LoadUrlhaus(string path, Dictionary<string, IocInfo> domains, Dictionary<string, IocInfo>? urls = null)
    {
        foreach (var line in ReadLines(path))
        {
            if (line.StartsWith('#') || line.Length == 0) continue;
            var f = SplitCsv(line);
            if (f.Count < 6 || !Uri.TryCreate(f[2], UriKind.Absolute, out var u)) continue;
            var info = new IocInfo("URLhaus", "distribución de malware", NullIfNone(f[6]), f.Count > 7 ? f[7] : null);
            urls?.TryAdd(f[2], info);
            if (IPAddress.TryParse(u.Host, out _)) continue;
            // URLhaus lista URLs, no dominios: en hostings compartidos (PyPI, GitHub, Discord CDN...) sólo vale la URL exacta.
            if (IsSharedHost(u.Host)) continue;
            domains.TryAdd(u.Host.ToLowerInvariant(), info);
        }
    }

    public static bool IsSharedHost(string host)
    {
        host = host.ToLowerInvariant();
        return SharedHosts.Any(s => host == s || host.EndsWith("." + s, StringComparison.Ordinal));
    }

    private static readonly string[] SharedHosts =
    [
        // CDNs públicas y de código (regresión: cdn.jsdelivr.net salía "Peligroso" por URLs de paquetes alojados ahí).
        "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "cloudflare.com", "githack.com", "statically.io",
        "gitcdn.link", "b-cdn.net", "akamaized.net", "akamaihd.net", "azureedge.net", "edgesuite.net", "fastly.net",
        "fastly.com", "cloudflarestorage.com", "cloudflare-ipfs.com", "bitbucket.io", "github.io", "gitlab.io",
        "sourceforge.io", "osdn.net", "huggingface.co", "kaggle.com", "notion.so", "canva.com", "wixsite.com",
        "weebly.com", "blogspot.com", "wordpress.com", "sites.google.com", "forms.gle", "s3.amazonaws.com",
        "pythonhosted.org", "pypi.org", "npmjs.org", "npmjs.com", "yarnpkg.com", "nuget.org", "rubygems.org", "crates.io",
        "sourceforge.net", "archive.org", "mega.nz", "mega.io", "gofile.io", "catbox.moe", "4shared.com", "box.com",
        "wetransfer.com", "we.tl", "yandex.ru", "yandex.net", "disk.yandex.com", "filebin.net", "tmpfiles.org", "file.io",
        "glitch.me", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "r2.dev", "herokuapp.com", "azurewebsites.net",
        "blob.core.windows.net", "web.core.windows.net", "storage.googleapis.com", "appspot.com", "digitaloceanspaces.com",
        "backblazeb2.com", "wasabisys.com", "ipfs.io", "dweb.link", "telegra.ph", "imgur.com", "i.imgur.com",
        "steamcommunity.com", "steamusercontent.com", "objects.githubusercontent.com", "codeload.github.com",
        "gitee.com", "googleapis.com", "live.com", "office.com", "microsoft.com", "windows.net", "google.com", "youtube.com",
        "facebook.com", "fbcdn.net", "dropboxusercontent.com", "ufile.io", "anonfiles.com", "pixeldrain.com", "files.fm",
        "github.com", "raw.githubusercontent.com", "githubusercontent.com", "cdn.discordapp.com", "discord.com",
        "drive.google.com", "docs.google.com", "dropbox.com", "onedrive.live.com", "1drv.ms", "bitbucket.org",
        "gitlab.com", "mediafire.com", "pastebin.com", "transfer.sh", "amazonaws.com", "cloudfront.net",
        "googleusercontent.com", "sharepoint.com", "web.app", "firebasestorage.googleapis.com",
    ];

    /// <summary>Feodo Tracker JSON: [{ip_address, port, status, malware, ...}].</summary>
    internal static void LoadFeodo(string path, Dictionary<string, IocInfo> ips, Dictionary<string, IocInfo> ipPorts)
    {
        if (!File.Exists(path)) throw new FileNotFoundException(path);
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        foreach (var e in doc.RootElement.EnumerateArray())
        {
            var ip = e.GetProperty("ip_address").GetString();
            if (ip is null) continue;
            var info = new IocInfo("Feodo Tracker", "servidor de control de botnet", e.TryGetProperty("malware", out var m) ? m.GetString() : null, null);
            ips.TryAdd(ip, info);
            if (e.TryGetProperty("port", out var port)) ipPorts.TryAdd($"{ip}:{port.GetRawText().Trim('"')}", info);
        }
    }

    /// <summary>LOLBAS JSON: [{Name, Commands:[{Category}], ...}].</summary>
    internal static Dictionary<string, HashSet<string>> LoadLolbas(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException(path);
        var result = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        foreach (var e in doc.RootElement.EnumerateArray())
        {
            var name = e.GetProperty("Name").GetString();
            if (name is null) continue;
            var cats = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (e.TryGetProperty("Commands", out var cmds) && cmds.ValueKind == JsonValueKind.Array)
                foreach (var c in cmds.EnumerateArray())
                    if (c.TryGetProperty("Category", out var cat) && cat.GetString() is { } s) cats.Add(s);
            result[name] = cats;
        }
        return result;
    }

    /// <summary>LOLDrivers JSON: [{Category, KnownVulnerableSamples:[{SHA256, SHA1, MD5, Filename}]}].</summary>
    internal static Dictionary<string, IocInfo> LoadLolDrivers(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException(path);
        var result = new Dictionary<string, IocInfo>(StringComparer.OrdinalIgnoreCase);
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        foreach (var d in doc.RootElement.EnumerateArray())
        {
            var category = d.TryGetProperty("Category", out var c) ? c.GetString() ?? "" : "";
            var cat = category.Contains("malicious", StringComparison.OrdinalIgnoreCase) ? "driver malicioso" : "driver vulnerable";
            if (!d.TryGetProperty("KnownVulnerableSamples", out var samples) || samples.ValueKind != JsonValueKind.Array) continue;
            foreach (var s in samples.EnumerateArray())
            {
                var file = s.TryGetProperty("Filename", out var fn) ? fn.GetString() : null;
                foreach (var prop in new[] { "SHA256", "SHA1", "MD5" })
                    if (s.TryGetProperty(prop, out var h) && h.GetString() is { Length: > 0 } hash)
                        result.TryAdd(hash.ToLowerInvariant(), new IocInfo("LOLDrivers", cat, file, null));
            }
        }
        return result;
    }

    /// <summary>
    /// authroot.stl: CTL firmada (PKCS#7). Las entradas confiables son OCTET STRINGs de 20 bytes
    /// (thumbprint SHA1) dentro de trustedSubjects.
    /// </summary>
    internal static HashSet<string> LoadAuthRoot(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException(path);
        var cms = new SignedCms();
        cms.Decode(File.ReadAllBytes(path));
        var content = cms.ContentInfo.Content;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CollectThumbprints(new AsnReader(content, AsnEncodingRules.BER), set, 0);
        return set;
    }

    /// <summary>
    /// Verifica la firma PKCS#7 de authroot.stl: firma criptográficamente válida, firmante de Microsoft y cadena
    /// hasta una raíz de Microsoft presente en el equipo. Lanza si algo no cierra.
    /// </summary>
    internal static void VerifyAuthRootSignature(string path)
    {
        var cms = new SignedCms();
        cms.Decode(File.ReadAllBytes(path));
        cms.CheckSignature(verifySignatureOnly: true);
        var signer = cms.SignerInfos[0].Certificate ?? throw new InvalidDataException("authroot.stl sin certificado firmante");
        if (!signer.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"authroot.stl firmado por un tercero: {signer.Subject}");

        using var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
        chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
        // La CTL se re-publica con el mismo firmante; puede estar fuera de vigencia sin timestamp.
        chain.ChainPolicy.VerificationFlags = System.Security.Cryptography.X509Certificates.X509VerificationFlags.IgnoreNotTimeValid;
        chain.ChainPolicy.ExtraStore.AddRange(cms.Certificates);
        if (!chain.Build(signer))
            throw new InvalidDataException("No se pudo validar la cadena del firmante de authroot.stl: " +
                string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation.Trim())));
        var root = chain.ChainElements[^1].Certificate;
        if (!root.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"La cadena de authroot.stl no termina en una raíz de Microsoft: {root.Subject}");
    }

    private static void CollectThumbprints(AsnReader reader, HashSet<string> set, int depth)
    {
        while (reader.HasData)
        {
            var tag = reader.PeekTag();
            if (tag.IsConstructed && depth < 8)
            {
                AsnReader inner;
                if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.Set)
                    inner = reader.ReadSetOf(skipSortOrderValidation: true);
                else if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.Sequence)
                    inner = reader.ReadSequence();
                else
                {
                    reader.ReadEncodedValue();
                    continue;
                }
                CollectThumbprints(inner, set, depth + 1);
            }
            else if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.OctetString)
            {
                var bytes = reader.ReadOctetString();
                if (bytes.Length == 20) set.Add(Convert.ToHexString(bytes));
            }
            else
            {
                reader.ReadEncodedValue();
            }
        }
    }

    private static string? NullIfNone(string s) => string.IsNullOrWhiteSpace(s) || s is "None" or "n/a" or "null" ? null : s;

    private static string ThreatTypeEs(string t) => t switch
    {
        "botnet_cc" => "servidor de control de malware",
        "payload_delivery" => "distribución de malware",
        "payload" => "malware",
        _ => t,
    };
}

public static class FeedNames
{
    public const string ThreatFox = "threatfox.csv";
    public const string Urlhaus = "urlhaus.csv";
    public const string Feodo = "feodo.json";
    public const string Lolbas = "lolbas.json";
    public const string LolDrivers = "loldrivers.json";
    public const string AuthRoot = "authroot.stl";
}
