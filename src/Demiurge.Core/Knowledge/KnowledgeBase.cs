using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Knowledge;

public sealed class KnowledgeEntry
{
    public string Id { get; set; } = "";
    /// <summary>binary | software | task | service | extension | cert</summary>
    public string Kind { get; set; } = "";
    public List<string> Names { get; set; } = new();
    /// <summary>Para entradas de software: ejecutables asociados.</summary>
    public List<string> Binaries { get; set; } = new();
    public List<string> Paths { get; set; } = new();
    public List<string> Signers { get; set; } = new();
    public string Title { get; set; } = "";
    public string What { get; set; } = "";
    public string Normal { get; set; } = "";
    /// <summary>benign | question | pup | suspicious</summary>
    public string Risk { get; set; } = "benign";
    public string Category { get; set; } = "";
    public List<string> Links { get; set; } = new();
    /// <summary>
    /// Sólo se considera benigna si hay un programa instalado cuyo nombre o editor contenga alguno de estos textos
    /// (evita que un malware se allowlistee poniéndole "Electronic Arts" a su certificado).
    /// </summary>
    public List<string> RequiresSoftware { get; set; } = new();

    public bool RequirementsMet(IEnumerable<InstalledSoftware> software) =>
        RequiresSoftware.Count == 0 || software.Any(s => RequiresSoftware.Any(r =>
            s.Name.Contains(r, StringComparison.OrdinalIgnoreCase) || (s.Publisher?.Contains(r, StringComparison.OrdinalIgnoreCase) ?? false)));
}

public sealed class KnowledgeMatch
{
    public required KnowledgeEntry Entry { get; init; }
    /// <summary>
    /// true si la entrada es benigna Y el binario cumple firmante/ubicación esperados. Sólo así cuenta
    /// para la allowlist dura: un "svchost.exe" en AppData matchea por nombre pero NO es confiable.
    /// </summary>
    public bool Trusted { get; init; }
    /// <summary>El nombre coincide con un binario conocido pero firma/ubicación no (posible suplantación).</summary>
    public bool Mismatch { get; init; }
}

/// <summary>
/// TI-12: base de conocimiento propia con explicaciones ATP ("¿Qué es esto?" / "¿Es normal?").
/// Embebida en el ensamblado y actualizable desde %ProgramData%\Demiurge\rules\knowledgebase.json.
/// </summary>
public sealed class KnowledgeBase
{
    private readonly List<KnowledgeEntry> _entries;
    private readonly Dictionary<string, List<KnowledgeEntry>> _byBinaryName = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, KnowledgeEntry> _byExtensionId = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, KnowledgeEntry> _byService = new(StringComparer.OrdinalIgnoreCase);

    public string Version { get; }
    public IReadOnlyList<KnowledgeEntry> Entries => _entries;

    private sealed class KbFile
    {
        public string Version { get; set; } = "";
        public List<KnowledgeEntry> Entries { get; set; } = new();
    }

    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    public KnowledgeBase(string json)
    {
        var file = JsonSerializer.Deserialize<KbFile>(json, JsonOpts) ?? new KbFile();
        Version = file.Version;
        _entries = file.Entries;
        foreach (var e in _entries)
        {
            switch (e.Kind)
            {
                case "binary":
                    foreach (var n in e.Names) Add(_byBinaryName, n, e);
                    break;
                case "software":
                    foreach (var n in e.Binaries) Add(_byBinaryName, n, e);
                    break;
                case "extension":
                    foreach (var n in e.Names) _byExtensionId.TryAdd(n, e);
                    break;
                case "service":
                    foreach (var n in e.Names) _byService.TryAdd(n, e);
                    break;
            }
        }
    }

    private static void Add(Dictionary<string, List<KnowledgeEntry>> d, string key, KnowledgeEntry e)
    {
        if (!d.TryGetValue(key, out var l)) d[key] = l = new();
        l.Add(e);
    }

    public static KnowledgeBase Load()
    {
        var external = Path.Combine(DemiurgePaths.Root, "rules", "knowledgebase.json"); // sin crear carpetas (ver RuleSet.Load)
        if (File.Exists(external) && Security.DataDirectoryLockdown.CanTrust(external))
        {
            try { return new KnowledgeBase(File.ReadAllText(external)); }
            catch
            {
                // archivo actualizado roto: usar el embebido
            }
        }
        return new KnowledgeBase(EmbeddedResource.Read("knowledgebase.json"));
    }

    public KnowledgeMatch? MatchBinary(BinaryInfo? b)
    {
        if (b is null) return null;
        if (!_byBinaryName.TryGetValue(Path.GetFileName(b.Path), out var candidates)) return null;

        KnowledgeMatch? best = null;
        foreach (var e in candidates)
        {
            bool signerOk = e.Signers.Count == 0
                ? false
                : b.Signature?.IsValid == true && e.Signers.Any(s => b.Signature.Signer?.Contains(s, StringComparison.OrdinalIgnoreCase) == true);
            bool pathOk = e.Paths.Count == 0 || e.Paths.Any(p => b.Path.StartsWith(Environment.ExpandEnvironmentVariables(p), StringComparison.OrdinalIgnoreCase));
            bool trusted = e.Risk == "benign" && signerOk && pathOk;
            var m = new KnowledgeMatch { Entry = e, Trusted = trusted, Mismatch = e.Signers.Count > 0 && (!signerOk || !pathOk) };
            if (best is null || (m.Trusted && !best.Trusted)) best = m;
        }
        return best;
    }

    public KnowledgeEntry? MatchSoftware(InstalledSoftware s) =>
        _entries.FirstOrDefault(e => e.Kind == "software" && e.Names.Any(n => s.Name.Contains(n, StringComparison.OrdinalIgnoreCase)));

    public KnowledgeEntry? MatchTask(string taskPath) =>
        _entries.FirstOrDefault(e => e.Kind == "task" && e.Names.Any(n => taskPath.StartsWith(n, StringComparison.OrdinalIgnoreCase) || taskPath.Contains(n, StringComparison.OrdinalIgnoreCase)));

    public KnowledgeEntry? MatchService(string name) => _byService.GetValueOrDefault(name);

    public KnowledgeEntry? MatchExtension(string id) => _byExtensionId.GetValueOrDefault(id);

    public KnowledgeEntry? MatchCertificate(string subject) =>
        _entries.FirstOrDefault(e => e.Kind == "cert" && e.Names.Any(n =>
            Regex.IsMatch(subject, $@"(^|[^\p{{L}}]){Regex.Escape(n)}($|[^\p{{L}}])", RegexOptions.IgnoreCase)));

    public KnowledgeEntry? ById(string? id) => id is null ? null : _entries.FirstOrDefault(e => e.Id == id);

    /// <summary>Software de acceso remoto conocido (H-17) por nombre de programa o de ejecutable.</summary>
    public IEnumerable<KnowledgeEntry> RemoteTools => _entries.Where(e => e.Category == "remote_tool");
}

internal static class EmbeddedResource
{
    public static string Read(string name)
    {
        var asm = Assembly.GetExecutingAssembly();
        using var s = asm.GetManifestResourceStream("Demiurge.Resources." + name)
            ?? throw new FileNotFoundException($"Recurso embebido no encontrado: {name}");
        using var sr = new StreamReader(s);
        return sr.ReadToEnd();
    }
}
