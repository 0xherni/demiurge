using System.Text.Json.Serialization;

namespace Demiurge.Core.Model;

/// <summary>
/// Toda entidad tiene una clave estable (para el diff entre escaneos y para colgarle findings).
/// </summary>
public interface IEntity
{
    [JsonIgnore] EntityKind Kind { get; }
    [JsonIgnore] string Key { get; }
    /// <summary>Nombre corto legible para mostrar al usuario.</summary>
    [JsonIgnore] string DisplayName { get; }
}

public sealed class ScanInfo
{
    public long Id { get; set; }
    public DateTimeOffset Started { get; set; }
    public DateTimeOffset? Finished { get; set; }
    public ScanType Type { get; set; }
    public string AppVersion { get; set; } = "";
    public string FeedsVersion { get; set; } = "";
    public GlobalVerdict? Verdict { get; set; }
    public int ScoreMax { get; set; }
    public string? HealthSummary { get; set; }
    /// <summary>Si el escaneo corrió con privilegios (SYSTEM/admin). Sin ellos se pierde visibilidad.</summary>
    public bool Elevated { get; set; }
    public string? Machine { get; set; }
}

public sealed class SignatureInfo
{
    public bool IsSigned { get; set; }
    public bool IsValid { get; set; }
    public bool IsCatalogSigned { get; set; }
    public string? Signer { get; set; }
    public string? Issuer { get; set; }
    public DateTimeOffset? SigningTime { get; set; }
    public string? Error { get; set; }

    [JsonIgnore]
    public bool IsMicrosoft => IsValid && Signer is not null &&
        (Signer.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase) ||
         Signer.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase));
}

public sealed class ReputationInfo
{
    public string Source { get; set; } = "";
    /// <summary>malicious | benign | unknown</summary>
    public string Verdict { get; set; } = "unknown";
    public string? Family { get; set; }
    public int? Detections { get; set; }
    public DateTimeOffset Fetched { get; set; }
}

public sealed class BinaryInfo : IEntity
{
    public string Path { get; set; } = "";
    public string? Sha256 { get; set; }
    public string? Sha1 { get; set; }
    public string? Md5 { get; set; }
    public long Size { get; set; }
    public DateTimeOffset? Created { get; set; }
    public DateTimeOffset? Modified { get; set; }
    public bool Exists { get; set; } = true;
    public SignatureInfo? Signature { get; set; }
    public List<ReputationInfo> Reputation { get; set; } = new();
    public string? KbId { get; set; }
    public string? ProductName { get; set; }
    public string? CompanyName { get; set; }
    public string? FileDescription { get; set; }

    public EntityKind Kind => EntityKind.Binary;
    public string Key => !string.IsNullOrEmpty(Sha256) ? Sha256! : "path:" + Path.ToLowerInvariant();
    public string DisplayName => System.IO.Path.GetFileName(Path);

    [JsonIgnore] public bool IsKnownGood => Reputation.Any(r => r.Verdict == "benign");
    [JsonIgnore] public ReputationInfo? Malicious => Reputation.FirstOrDefault(r => r.Verdict == "malicious");
}

public sealed class ProcessInfo : IEntity
{
    public int Pid { get; set; }
    public int ParentPid { get; set; }
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public string? CommandLine { get; set; }
    public string? User { get; set; }
    public int SessionId { get; set; }
    public DateTimeOffset? StartTime { get; set; }
    public DateTimeOffset? EndTime { get; set; }
    public string? Integrity { get; set; }
    public bool Elevated { get; set; }
    public double CpuPercent { get; set; }
    public long WorkingSetBytes { get; set; }
    public double? GpuPercent { get; set; }
    public string? BinaryKey { get; set; }
    /// <summary>Visto sólo por telemetría en vivo (vida corta).</summary>
    public bool Ephemeral { get; set; }

    public EntityKind Kind => EntityKind.Process;
    public string Key => $"{Pid}:{StartTime?.ToUnixTimeMilliseconds() ?? 0}";
    public string DisplayName => Name;
}

public sealed class PersistenceItem : IEntity
{
    public PersistenceType Type { get; set; }
    /// <summary>Ubicación: clave de registro, ruta de tarea, carpeta Startup, nombre de servicio, etc.</summary>
    public string Location { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Command { get; set; }
    public string? ResolvedPath { get; set; }
    public string? Arguments { get; set; }
    public string? Author { get; set; }
    public string? RunAs { get; set; }
    public bool Hidden { get; set; }
    public bool Enabled { get; set; } = true;
    public string? BinaryKey { get; set; }
    public Dictionary<string, string> Extra { get; set; } = new();

    public EntityKind Kind => EntityKind.Persistence;
    public string Key => $"{Type}|{Location}|{Name}".ToLowerInvariant();
    public string DisplayName => string.IsNullOrEmpty(Name) ? Location : Name;
}

public sealed class ConnectionInfo : IEntity
{
    public int Pid { get; set; }
    public string Protocol { get; set; } = "TCP";
    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string? RemoteAddress { get; set; }
    public int RemotePort { get; set; }
    public string State { get; set; } = "";
    public long BytesOut { get; set; }
    public long BytesIn { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessPath { get; set; }
    public string? TiMatch { get; set; }

    public EntityKind Kind => EntityKind.Connection;
    public string Key => $"{Protocol}|{ProcessPath ?? ProcessName}|{RemoteAddress}:{RemotePort}|{LocalPort}".ToLowerInvariant();
    public string DisplayName => RemoteAddress is null ? $"{Protocol} :{LocalPort} (escucha)" : $"{RemoteAddress}:{RemotePort}";

    [JsonIgnore] public bool IsListening => State.Equals("Listen", StringComparison.OrdinalIgnoreCase) || (Protocol == "UDP" && RemoteAddress is null);
}

public sealed class DnsQueryInfo : IEntity
{
    public int? Pid { get; set; }
    public string Domain { get; set; } = "";
    public string? RecordType { get; set; }
    public string? Response { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public string? ProcessName { get; set; }
    public string? TiMatch { get; set; }
    public string Source { get; set; } = "cache";

    public EntityKind Kind => EntityKind.DnsQuery;
    public string Key => Domain.ToLowerInvariant();
    public string DisplayName => Domain;
}

public sealed class ModuleLoadInfo : IEntity
{
    public int Pid { get; set; }
    public string Path { get; set; } = "";
    public string? ProcessName { get; set; }
    public string? BinaryKey { get; set; }
    public DateTimeOffset Timestamp { get; set; }

    public EntityKind Kind => EntityKind.ModuleLoad;
    public string Key => $"{ProcessName}|{Path}".ToLowerInvariant();
    public string DisplayName => System.IO.Path.GetFileName(Path);
}

public sealed class BrowserExtension : IEntity
{
    public string Browser { get; set; } = "";
    public string Profile { get; set; } = "";
    public string User { get; set; } = "";
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Version { get; set; }
    public List<string> Permissions { get; set; } = new();
    /// <summary>store | sideload | policy | component | unknown</summary>
    public string Origin { get; set; } = "unknown";
    public bool Enabled { get; set; } = true;
    public string? UpdateUrl { get; set; }
    public string? ProfilePath { get; set; }

    public EntityKind Kind => EntityKind.Extension;
    public string Key => $"{Browser}|{User}|{Profile}|{Id}".ToLowerInvariant();
    public string DisplayName => Name;
}

/// <summary>Buscador / homepage / permisos de notificación por perfil de navegador.</summary>
public sealed class BrowserSettingInfo : IEntity
{
    public string Browser { get; set; } = "";
    public string Profile { get; set; } = "";
    public string User { get; set; } = "";
    /// <summary>search_engine | homepage | startup_url | notifications | policy</summary>
    public string Setting { get; set; } = "";
    public string Value { get; set; } = "";
    public string? ProfilePath { get; set; }

    public EntityKind Kind => EntityKind.BrowserSetting;
    public string Key => $"{Browser}|{User}|{Profile}|{Setting}|{Value}".ToLowerInvariant();
    public string DisplayName => $"{Browser} ({Profile}): {Setting}";
}

public sealed class InstalledSoftware : IEntity
{
    public string Name { get; set; } = "";
    public string? Publisher { get; set; }
    public string? Version { get; set; }
    public DateTimeOffset? InstallDate { get; set; }
    public string? InstallLocation { get; set; }
    public string? UninstallString { get; set; }
    /// <summary>remote_tool | pup | null</summary>
    public string? Category { get; set; }
    public string? KbId { get; set; }
    public string Scope { get; set; } = "machine";

    public EntityKind Kind => EntityKind.InstalledSoftware;
    public string Key => $"{Name}|{Publisher}".ToLowerInvariant();
    public string DisplayName => Name;
}

public sealed class LocalAccount : IEntity
{
    public string Name { get; set; } = "";
    public string? Sid { get; set; }
    public bool Enabled { get; set; }
    public bool IsAdmin { get; set; }
    public DateTimeOffset? Created { get; set; }
    public DateTimeOffset? LastLogon { get; set; }
    public List<string> Groups { get; set; } = new();
    public bool BuiltIn { get; set; }

    public EntityKind Kind => EntityKind.Account;
    public string Key => (Sid ?? Name).ToLowerInvariant();
    public string DisplayName => Name;
}

public sealed class CertificateInfo : IEntity
{
    public string Subject { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string Thumbprint { get; set; } = "";
    public string Store { get; set; } = "";
    public DateTimeOffset NotBefore { get; set; }
    public DateTimeOffset NotAfter { get; set; }
    public bool? InAuthRoot { get; set; }

    public EntityKind Kind => EntityKind.Certificate;
    public string Key => $"{Store}|{Thumbprint}".ToLowerInvariant();
    public string DisplayName => Subject;
}

public sealed class SystemSetting : IEntity
{
    /// <summary>defender_rtp, firewall_public, uac, rdp, hosts, proxy, dns, ...</summary>
    public string Name { get; set; } = "";
    public string? Value { get; set; }
    public string? Expected { get; set; }
    /// <summary>true = está como se espera, false = no, null = no se pudo determinar.</summary>
    public bool? Ok { get; set; }
    /// <summary>infection | health (no mezclar postura con infección).</summary>
    public string Category { get; set; } = "health";
    public string? Detail { get; set; }
    /// <summary>Origen del valor (p.ej. "static"/"dhcp" para DNS, "WinINET"/"WinHTTP" para proxy).</summary>
    public string? Source { get; set; }

    public EntityKind Kind => EntityKind.SystemSetting;
    public string Key => $"{Name}|{Value}".ToLowerInvariant();
    public string DisplayName => Name;
}

public sealed class EventInfo : IEntity
{
    public string Log { get; set; } = "";
    public int EventId { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public string? Provider { get; set; }
    public Dictionary<string, string> Data { get; set; } = new();
    public string? Message { get; set; }
    public long RecordId { get; set; }
    public string Source { get; set; } = "eventlog";

    public EntityKind Kind => EntityKind.Event;
    public string Key => $"{Log}|{RecordId}|{EventId}".ToLowerInvariant();
    public string DisplayName => $"{Log} #{EventId}";
}

public sealed class RecentFile : IEntity
{
    public string Path { get; set; } = "";
    public DateTimeOffset Created { get; set; }
    public DateTimeOffset Modified { get; set; }
    public long Size { get; set; }
    public int? ZoneId { get; set; }
    public string? HostUrl { get; set; }
    public string? ReferrerUrl { get; set; }
    public bool DoubleExtension { get; set; }
    public string? BinaryKey { get; set; }

    public EntityKind Kind => EntityKind.RecentFile;
    public string Key => Path.ToLowerInvariant();
    public string DisplayName => System.IO.Path.GetFileName(Path);
}

public sealed class DriverInfo : IEntity
{
    public string Name { get; set; } = "";
    public string? DisplayName2 { get; set; }
    public string? Path { get; set; }
    public string? State { get; set; }
    public string? StartMode { get; set; }
    public string? BinaryKey { get; set; }

    public EntityKind Kind => EntityKind.Driver;
    public string Key => Name.ToLowerInvariant();
    public string DisplayName => DisplayName2 ?? Name;
}

public sealed class DefenderStatus
{
    public bool? AntivirusEnabled { get; set; }
    public bool? RealTimeProtectionEnabled { get; set; }
    public bool? TamperProtected { get; set; }
    public DateTimeOffset? SignatureLastUpdated { get; set; }
    public int? SignatureAgeDays { get; set; }
    public List<string> ExclusionPaths { get; set; } = new();
    public List<string> ExclusionProcesses { get; set; } = new();
    public List<string> ExclusionExtensions { get; set; } = new();
    public List<string> OtherAntivirus { get; set; } = new();
    public List<DefenderDetection> Detections { get; set; } = new();
    public bool Available { get; set; }
}

public sealed class DefenderDetection
{
    public string ThreatName { get; set; } = "";
    public DateTimeOffset? Time { get; set; }
    public List<string> Resources { get; set; } = new();
    public string? Action { get; set; }
}

/// <summary>
/// COL-27: algo que se ejecutó en la PC, según los rastros que deja Windows (BAM, UserAssist, PCA, Prefetch).
/// Sirve para ver programas que corrieron aunque ya se hayan borrado (típico de stealers y droppers).
/// </summary>
public sealed class ExecutionRecord : IEntity
{
    /// <summary>Ruta completa si la fuente la da (BAM, UserAssist, PCA); null si sólo se conoce el nombre (Prefetch).</summary>
    public string? Path { get; set; }
    public string Name { get; set; } = "";
    public List<string> Sources { get; set; } = new();
    public DateTimeOffset? LastRun { get; set; }
    public DateTimeOffset? FirstRun { get; set; }
    public int? RunCount { get; set; }
    public string? User { get; set; }
    /// <summary>Si el archivo sigue en el disco.</summary>
    public bool? Exists { get; set; }
    public string? BinaryKey { get; set; }

    public EntityKind Kind => EntityKind.Execution;
    public string Key => "exec:" + (Path ?? Name).ToLowerInvariant();
    public string DisplayName => Name;
}

/// <summary>COL-28: regla del Firewall de Windows.</summary>
public sealed class FirewallRule : IEntity
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>Allow | Block</summary>
    public string Action { get; set; } = "";
    /// <summary>In | Out</summary>
    public string Direction { get; set; } = "";
    public bool Active { get; set; }
    public string? App { get; set; }
    public string? Service { get; set; }
    public string? Protocol { get; set; }
    public string? LocalPorts { get; set; }
    public string? RemoteAddresses { get; set; }
    public string? Profiles { get; set; }
    public string? Group { get; set; }
    /// <summary>Regla que trae Windows (nombre o grupo con referencia a recurso "@...").</summary>
    public bool BuiltIn { get; set; }
    /// <summary>local | policy</summary>
    public string Store { get; set; } = "local";
    public string? BinaryKey { get; set; }

    public EntityKind Kind => EntityKind.FirewallRule;
    public string Key => $"fw:{Store}|{Id}".ToLowerInvariant();
    public string DisplayName => Name;
}
