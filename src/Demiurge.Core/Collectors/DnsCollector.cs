using System.Diagnostics.Eventing.Reader;
using Demiurge.Core.Model;
using Demiurge.Core.Native;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-16 (y COL-05 sin ETW): dominios consultados. Fuentes, en orden de calidad:
/// 1) log DNS-Client/Operational si está habilitado (dominio + PID),
/// 2) caché DNS (sin PID).
/// </summary>
public sealed class DnsCollector : ICollector
{
    public string Id => "COL-05/16";
    public string Name => "Dominios consultados";
    public int Order => 20;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var byDomain = new Dictionary<string, DnsQueryInfo>(StringComparer.OrdinalIgnoreCase);
        var procs = ctx.Snapshot.Processes.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First().Name);

        foreach (var q in ReadOperationalLog(procs, ct))
            byDomain.TryAdd(q.Domain, q);

        foreach (var e in DnsCache.Read())
        {
            var name = e.Name.TrimEnd('.');
            if (name.Length == 0) continue;
            byDomain.TryAdd(name, new DnsQueryInfo { Domain = name, RecordType = e.Type, Timestamp = DateTimeOffset.Now, Source = "cache" });
        }

        ctx.Snapshot.AddRange(ctx.Snapshot.DnsQueries, byDomain.Values);
        return Task.FromResult(CollectorResult.Of(byDomain.Count));
    }

    private static IEnumerable<DnsQueryInfo> ReadOperationalLog(Dictionary<int, string> procs, CancellationToken ct)
    {
        var list = new List<DnsQueryInfo>();
        try
        {
            var query = new EventLogQuery("Microsoft-Windows-DNS-Client/Operational", PathType.LogName,
                "*[System[(EventID=3006 or EventID=3008 or EventID=3020) and TimeCreated[timediff(@SystemTime) <= 86400000]]]")
            { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            int n = 0;
            for (var e = reader.ReadEvent(); e is not null && n < 20000; e = reader.ReadEvent(), n++)
            {
                ct.ThrowIfCancellationRequested();
                using (e)
                {
                    var name = e.Properties.Count > 0 ? e.Properties[0].Value?.ToString() : null;
                    if (string.IsNullOrEmpty(name)) continue;
                    int? pid = e.ProcessId;
                    list.Add(new DnsQueryInfo
                    {
                        Domain = name.TrimEnd('.'),
                        Pid = pid,
                        ProcessName = pid is int p && procs.TryGetValue(p, out var pn) ? pn : null,
                        Timestamp = e.TimeCreated ?? DateTime.Now,
                        Source = "eventlog",
                    });
                }
            }
        }
        catch
        {
            // log deshabilitado (default en Windows) o sin permisos
        }
        return list;
    }
}
