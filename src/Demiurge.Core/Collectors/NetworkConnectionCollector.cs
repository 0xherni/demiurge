using Demiurge.Core.Model;
using Demiurge.Core.Native;

namespace Demiurge.Core.Collectors;

/// <summary>COL-14: conexiones activas y puertos en escucha por PID.</summary>
public sealed class NetworkConnectionCollector : ICollector
{
    public string Id => "COL-14";
    public string Name => "Conexiones de red";
    public int Order => 20;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var procs = ctx.Snapshot.Processes.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First());
        var now = DateTimeOffset.Now;
        var list = new List<ConnectionInfo>();
        foreach (var row in IpHelper.GetAll())
        {
            if (row.State is "TimeWait" or "Closed" or "DeleteTcb") continue;
            procs.TryGetValue(row.Pid, out var proc);
            list.Add(new ConnectionInfo
            {
                Pid = row.Pid,
                Protocol = row.Protocol,
                LocalAddress = row.Local.ToString(),
                LocalPort = row.LocalPort,
                RemoteAddress = row.Remote?.ToString(),
                RemotePort = row.RemotePort,
                State = row.Protocol == "UDP" ? "Listen" : row.State,
                Timestamp = now,
                ProcessName = proc?.Name,
                ProcessPath = proc?.Path,
            });
        }
        ctx.Snapshot.AddRange(ctx.Snapshot.Connections, list);
        return Task.FromResult(CollectorResult.Of(list.Count));
    }
}
