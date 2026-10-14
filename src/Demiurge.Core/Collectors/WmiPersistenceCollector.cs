using System.Management;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-12: persistencia WMI en root\subscription (__EventFilter, consumers, bindings).
/// Persistencia fileless clásica; en una PC doméstica casi siempre es maliciosa.
/// </summary>
public sealed class WmiPersistenceCollector : ICollector
{
    public string Id => "COL-12";
    public string Name => "Arranque: WMI";
    public int Order => 20;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var scope = new ManagementScope(@"\\.\root\subscription");
        scope.Connect();

        var filters = Query(scope, "SELECT Name, Query FROM __EventFilter")
            .ToDictionary(m => m["Name"]?.ToString() ?? "", m => m["Query"]?.ToString() ?? "");

        var bindings = Query(scope, "SELECT Filter, Consumer FROM __FilterToConsumerBinding")
            .Select(m => (filter: m["Filter"]?.ToString() ?? "", consumer: m["Consumer"]?.ToString() ?? ""))
            .ToList();

        var items = new List<PersistenceItem>();
        foreach (var (cls, field) in new[] { ("CommandLineEventConsumer", "CommandLineTemplate"), ("ActiveScriptEventConsumer", "ScriptText") })
        {
            foreach (var mo in Query(scope, $"SELECT * FROM {cls}"))
            {
                ct.ThrowIfCancellationRequested();
                var name = mo["Name"]?.ToString() ?? "";
                var body = mo[field]?.ToString();
                if (cls == "ActiveScriptEventConsumer" && string.IsNullOrEmpty(body))
                    body = mo["ScriptFileName"]?.ToString();
                if (cls == "CommandLineEventConsumer" && string.IsNullOrEmpty(body))
                    body = mo["ExecutablePath"]?.ToString();

                var binding = bindings.FirstOrDefault(b => b.consumer.Contains($"Name=\"{name}\"", StringComparison.OrdinalIgnoreCase));
                var filterName = ExtractName(binding.filter);
                var filterQuery = filterName is not null ? filters.GetValueOrDefault(filterName) : null;

                string? target = null;
                if (cls == "CommandLineEventConsumer")
                {
                    var r = CommandLineResolver.Resolve(body);
                    target = r.HostedModule ?? r.Executable;
                }

                items.Add(new PersistenceItem
                {
                    Type = PersistenceType.Wmi,
                    Location = @"root\subscription\" + cls,
                    Name = name,
                    Command = body,
                    ResolvedPath = target,
                    BinaryKey = ctx.Binaries.Register(target),
                    Extra =
                    {
                        ["consumerClass"] = cls,
                        ["filter"] = filterName ?? "",
                        ["filterQuery"] = filterQuery ?? "",
                        ["bound"] = (binding.consumer is { Length: > 0 }).ToString(),
                    },
                });
                mo.Dispose();
            }
        }

        ctx.Snapshot.AddRange(ctx.Snapshot.Persistence, items);
        return Task.FromResult(CollectorResult.Of(items.Count));
    }

    private static List<ManagementBaseObject> Query(ManagementScope scope, string q)
    {
        try
        {
            using var s = new ManagementObjectSearcher(scope, new ObjectQuery(q));
            return s.Get().Cast<ManagementBaseObject>().ToList();
        }
        catch (ManagementException)
        {
            return new();
        }
    }

    private static string? ExtractName(string path)
    {
        int i = path.IndexOf("Name=\"", StringComparison.OrdinalIgnoreCase);
        if (i < 0) return null;
        int j = path.IndexOf('"', i + 6);
        return j > i ? path[(i + 6)..j] : null;
    }
}
