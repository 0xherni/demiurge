using System.Text.Json;
using Demiurge.Core.Util;

namespace Demiurge.Core;

/// <summary>Configuración persistida en %ProgramData%\Demiurge\config.json.</summary>
public sealed class DemiurgeOptions
{
    /// <summary>Consultas online por hash (CIRCL, MalwareBazaar). Nunca se suben archivos.</summary>
    public bool OnlineHashLookups { get; set; } = true;

    /// <summary>API key de VirusTotal del propio usuario (TI-08, opcional).</summary>
    public string? VirusTotalApiKey { get; set; }
    /// <summary>H-01: mínimo de motores de VT para considerar malicioso.</summary>
    public int VirusTotalMinDetections { get; set; } = 5;

    /// <summary>Auth-Key gratuita de abuse.ch (las APIs pueden requerirla).</summary>
    public string? AbuseChAuthKey { get; set; }

    public int FeedUpdateHours { get; set; } = 6;
    public int ReputationTtlHours { get; set; } = 72;

    /// <summary>COL-25: antigüedad máxima de archivos recientes.</summary>
    public int RecentFilesDays { get; set; } = 30;
    public int RecentFilesMaxDepth { get; set; } = 3;

    /// <summary>COL-23: ventana de event logs.</summary>
    public int EventLogDays { get; set; } = 7;

    /// <summary>COL-26: ventana de medición de recursos (no reaccionar a picos).</summary>
    public int ResourceWindowSeconds { get; set; } = 20;

    public int CollectorTimeoutSeconds { get; set; } = 180;


    /// <summary>
    /// Herramientas externas. YARA-X y HollowsHunter vienen con el instalador (activadas por defecto);
    /// Hayabusa es opcional y hay que traerla aparte.
    /// </summary>
    public ExternalToolOptions YaraX { get; set; } = new() { FileName = "yr.exe", Enabled = true };
    public ExternalToolOptions HollowsHunter { get; set; } = new() { FileName = "hollows_hunter.exe", Enabled = true };
    public ExternalToolOptions Hayabusa { get; set; } = new() { FileName = "hayabusa.exe" };

    /// <summary>Pedirle a Microsoft Defender que analice los archivos sospechosos (sin dejar que los borre solo).</summary>
    public bool DefenderScanEnabled { get; set; } = true;
    public bool SysmonOptIn { get; set; }

    public string Language { get; set; } = "es-AR";

    /// <summary>
    /// Permite que procesos sin elevar lean el detalle (inventario, hallazgos, diff). Apagado por defecto: el detalle
    /// incluye rutas y líneas de comando de todos los usuarios. Útil para el servidor MCP. Sólo lo cambia un admin.
    /// </summary>
    public bool AllowUnelevatedReads { get; set; }

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static DemiurgeOptions Load()
    {
        try
        {
            if (File.Exists(DemiurgePaths.Config) && Security.DataDirectoryLockdown.CanTrust(DemiurgePaths.Config))
                return Link(JsonSerializer.Deserialize<DemiurgeOptions>(File.ReadAllText(DemiurgePaths.Config)) ?? new());
        }
        catch
        {
            // config corrupta: defaults
        }
        return Link(new DemiurgeOptions());
    }

    /// <summary>Asocia cada herramienta con su entrada en tools.lock.json (no se guarda en la config).</summary>
    private static DemiurgeOptions Link(DemiurgeOptions o)
    {
        o.YaraX.LockId = "yarax";
        o.YaraX.FileName = "yr.exe";
        o.HollowsHunter.LockId = "hollowshunter";
        o.HollowsHunter.FileName = "hollows_hunter.exe";
        return o;
    }

    public void Save()
    {
        Directory.CreateDirectory(DemiurgePaths.Root);
        File.WriteAllText(DemiurgePaths.Config, JsonSerializer.Serialize(this, Json));
    }
}

public sealed class ExternalToolOptions
{
    public bool Enabled { get; set; }
    public string FileName { get; set; } = "";
    /// <summary>Ruta explícita; si es null se busca en %ProgramData%\Demiurge\tools.</summary>
    public string? Path { get; set; }
    /// <summary>SHA256 esperado del binario: se verifica antes de ejecutarlo.</summary>
    public string? ExpectedSha256 { get; set; }
    public int TimeoutSeconds { get; set; } = 900;
    public string? RulesPath { get; set; }
    /// <summary>Clave en tools.lock.json si la herramienta viene con el instalador.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string? LockId { get; set; }
}
