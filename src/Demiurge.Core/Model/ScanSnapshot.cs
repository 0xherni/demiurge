using System.Collections.Concurrent;

namespace Demiurge.Core.Model;

/// <summary>
/// Resultado completo de un escaneo: inventario + findings + scores + veredicto.
/// Se guarda entero en SQLite para el diff con el escaneo anterior.
/// </summary>
public sealed class ScanSnapshot
{
    public ScanInfo Scan { get; set; } = new();

    // Inventario (lo llenan los colectores; listas thread-safe vía Add* helpers).
    public List<ProcessInfo> Processes { get; set; } = new();
    public List<PersistenceItem> Persistence { get; set; } = new();
    public List<ConnectionInfo> Connections { get; set; } = new();
    public List<DnsQueryInfo> DnsQueries { get; set; } = new();
    public List<ModuleLoadInfo> ModuleLoads { get; set; } = new();
    public List<BrowserExtension> Extensions { get; set; } = new();
    public List<BrowserSettingInfo> BrowserSettings { get; set; } = new();
    public List<InstalledSoftware> Software { get; set; } = new();
    public List<LocalAccount> Accounts { get; set; } = new();
    public List<CertificateInfo> Certificates { get; set; } = new();
    public List<SystemSetting> Settings { get; set; } = new();
    public List<EventInfo> Events { get; set; } = new();
    public List<RecentFile> RecentFiles { get; set; } = new();
    public List<DriverInfo> Drivers { get; set; } = new();
    public DefenderStatus Defender { get; set; } = new();
    public List<string> HostsEntries { get; set; } = new();

    /// <summary>Binarios indexados por clave (sha256 o path).</summary>
    public Dictionary<string, BinaryInfo> Binaries { get; set; } = new();

    /// <summary>Hallazgos de herramientas externas (YARA-X, HollowsHunter, Hayabusa) antes de pasar a findings.</summary>
    public List<ExternalDetection> ExternalDetections { get; set; } = new();

    // Resultado del análisis.
    public List<Finding> Findings { get; set; } = new();
    public List<EntityScore> Scores { get; set; } = new();
    public GlobalVerdict Verdict { get; set; }
    public string VerdictText { get; set; } = "";
    public HealthReport Health { get; set; } = new();
    public List<CollectorStatus> Collectors { get; set; } = new();

    private readonly object _lock = new();

    public void Add<T>(List<T> list, T item) { lock (_lock) list.Add(item); }
    public void AddRange<T>(List<T> list, IEnumerable<T> items) { lock (_lock) list.AddRange(items); }

    public IEnumerable<IEntity> AllEntities()
    {
        foreach (var b in Binaries.Values) yield return b;
        foreach (var x in Processes) yield return x;
        foreach (var x in Persistence) yield return x;
        foreach (var x in Connections) yield return x;
        foreach (var x in DnsQueries) yield return x;
        foreach (var x in ModuleLoads) yield return x;
        foreach (var x in Extensions) yield return x;
        foreach (var x in BrowserSettings) yield return x;
        foreach (var x in Software) yield return x;
        foreach (var x in Accounts) yield return x;
        foreach (var x in Certificates) yield return x;
        foreach (var x in Settings) yield return x;
        foreach (var x in Events) yield return x;
        foreach (var x in RecentFiles) yield return x;
        foreach (var x in Drivers) yield return x;
    }

    public BinaryInfo? GetBinary(string? key) =>
        key is not null && Binaries.TryGetValue(key, out var b) ? b : null;
}

public sealed class ExternalDetection
{
    /// <summary>EXT-01 | EXT-02 | EXT-03 | EXT-04</summary>
    public string Tool { get; set; } = "";
    public string Rule { get; set; } = "";
    public string? Family { get; set; }
    public string? Level { get; set; }
    public string? TargetPath { get; set; }
    public int? Pid { get; set; }
    public List<string> AttackIds { get; set; } = new();
    public Dictionary<string, string> Data { get; set; } = new();
}
