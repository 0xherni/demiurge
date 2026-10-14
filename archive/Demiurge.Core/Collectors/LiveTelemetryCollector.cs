using Demiurge.Core.Live;
using Demiurge.Core.Model;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-02 / COL-03 / COL-04 (v2): incorpora al escaneo lo que vio el modo vivo — procesos efímeros,
/// DLLs cargadas fuera de rutas del sistema y bytes enviados/recibidos por conexión.
/// </summary>
public sealed class LiveTelemetryCollector : ICollector
{
    private readonly ILiveTelemetrySource? _live;

    public LiveTelemetryCollector(ILiveTelemetrySource? live) => _live = live;

    public string Id => "COL-02/03/04";
    public string Name => "Telemetría en vivo";
    public int Order => 30; // después de COL-01 y COL-14 para poder cruzar

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        if (_live is null || !_live.IsRunning)
            return Task.FromResult(new CollectorResult { Warnings = { "Modo vivo no activo: sin telemetría ETW" } });

        int count = 0;
        var known = ctx.Snapshot.Processes.Select(p => p.Pid).ToHashSet();

        // Procesos que ya terminaron (incluye los de milisegundos).
        foreach (var p in _live.RecentProcesses())
        {
            ct.ThrowIfCancellationRequested();
            if (known.Contains(p.Pid) && !p.Ephemeral) continue;
            p.BinaryKey = ctx.Binaries.Register(p.Path);
            ctx.Snapshot.Add(ctx.Snapshot.Processes, p);
            count++;
        }

        // Image loads (ya filtrados a rutas fuera de Windows/Program Files).
        var procs = ctx.Snapshot.Processes.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First());
        foreach (var m in _live.RecentModuleLoads().GroupBy(m => m.Key).Select(g => g.First()))
        {
            ct.ThrowIfCancellationRequested();
            m.BinaryKey = ctx.Binaries.Register(m.Path);
            if (m.ProcessName is null && procs.TryGetValue(m.Pid, out var pr)) m.ProcessName = pr.Name;
            ctx.Snapshot.Add(ctx.Snapshot.ModuleLoads, m);
            count++;
        }

        // Bytes por conexión: enriquecer las del snapshot y agregar las que ya se cerraron.
        foreach (var f in _live.RecentFlows())
        {
            var conn = ctx.Snapshot.Connections.FirstOrDefault(c =>
                c.Pid == f.Pid && c.RemoteAddress == f.RemoteAddress && c.RemotePort == f.RemotePort);
            if (conn is null)
            {
                procs.TryGetValue(f.Pid, out var pr);
                conn = new ConnectionInfo
                {
                    Pid = f.Pid,
                    Protocol = f.Protocol,
                    RemoteAddress = f.RemoteAddress,
                    RemotePort = f.RemotePort,
                    State = "Closed",
                    Timestamp = f.Last,
                    ProcessName = f.ProcessName ?? pr?.Name,
                    ProcessPath = pr?.Path,
                };
                ctx.Snapshot.Add(ctx.Snapshot.Connections, conn);
            }
            conn.BytesOut = f.BytesOut;
            conn.BytesIn = f.BytesIn;
            if (f.Connects.Count >= 4)
                ctx.Snapshot.Add(ctx.Snapshot.Flows, f);
            count++;
        }

        return Task.FromResult(CollectorResult.Of(count));
    }
}
