using Demiurge.Core.Model;

namespace Demiurge.Core.Live;

/// <summary>
/// Lo que el modo vivo (ETW) vio desde que arrancó el servicio. Los escaneos lo consumen para
/// sumar procesos efímeros, image loads, bytes por conexión y DNS por proceso.
/// </summary>
public interface ILiveTelemetrySource
{
    bool IsRunning { get; }
    IReadOnlyList<DnsQueryInfo> RecentDnsQueries();
    IReadOnlyList<ProcessInfo> RecentProcesses();
    IReadOnlyList<ModuleLoadInfo> RecentModuleLoads();
    IReadOnlyList<NetworkFlow> RecentFlows();
}

/// <summary>Agregado de tráfico por proceso y destino (COL-04).</summary>
public sealed class NetworkFlow
{
    public int Pid { get; set; }
    public string? ProcessName { get; set; }
    public string Protocol { get; set; } = "TCP";
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public long BytesOut { get; set; }
    public long BytesIn { get; set; }
    public DateTimeOffset First { get; set; }
    public DateTimeOffset Last { get; set; }
    /// <summary>Instantes de conexión (para detectar beaconing, H-25). Acotado.</summary>
    public List<DateTimeOffset> Connects { get; set; } = new();
}

/// <summary>Evento del modo vivo para la UI (notificaciones).</summary>
public sealed class LiveEvent
{
    /// <summary>process | connection | dns | persistence</summary>
    public string Type { get; set; } = "";
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.Now;
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    public int Score { get; set; }
    public List<string> HeuristicIds { get; set; } = new();
    public string? EntityKey { get; set; }
}
