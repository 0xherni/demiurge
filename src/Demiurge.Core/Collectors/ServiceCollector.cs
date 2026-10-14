using System.ServiceProcess;
using Microsoft.Win32;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>COL-11: servicios Win32 y su ImagePath (o ServiceDll para los alojados en svchost).</summary>
public sealed class ServiceCollector : ICollector
{
    public string Id => "COL-11";
    public string Name => "Arranque: servicios";
    public int Order => 20;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var items = new List<PersistenceItem>();
        var status = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var sc in ServiceController.GetServices())
                using (sc) { try { status[sc.ServiceName] = sc.Status.ToString(); } catch { } }
        }
        catch
        {
            // SCM no disponible
        }

        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (services is null) return Task.FromResult(CollectorResult.Of(0));

        foreach (var name in services.GetSubKeyNames())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var k = services.OpenSubKey(name);
                if (k is null) continue;
                int type = k.GetValue("Type") is int t ? t : 0;
                // 0x10 own process, 0x20 share process (+0x50/0x60 per-user). Drivers (1/2) los cubre COL-24.
                if ((type & 0x30) == 0) continue;
                var imagePath = k.GetValue("ImagePath")?.ToString();
                if (string.IsNullOrWhiteSpace(imagePath)) continue;

                string? serviceDll = null;
                using (var p = k.OpenSubKey("Parameters"))
                    serviceDll = p?.GetValue("ServiceDll")?.ToString();
                serviceDll ??= k.GetValue("ServiceDll")?.ToString();

                var r = CommandLineResolver.Resolve(imagePath);
                var target = serviceDll is not null ? Environment.ExpandEnvironmentVariables(serviceDll) : r.Executable;
                int start = k.GetValue("Start") is int s ? s : -1;

                items.Add(new PersistenceItem
                {
                    Type = PersistenceType.Service,
                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{name}",
                    Name = name,
                    Command = imagePath,
                    ResolvedPath = target,
                    Arguments = r.Arguments,
                    RunAs = k.GetValue("ObjectName")?.ToString(),
                    Enabled = start is 0 or 1 or 2 or 3,
                    BinaryKey = ctx.Binaries.Register(target),
                    Extra =
                    {
                        ["displayName"] = ResolveDisplayName(k.GetValue("DisplayName")?.ToString(), name),
                        ["startType"] = start switch { 0 => "Boot", 1 => "System", 2 => "Automático", 3 => "Manual", 4 => "Deshabilitado", _ => "?" },
                        ["state"] = status.GetValueOrDefault(name, "?"),
                        ["serviceDll"] = serviceDll ?? "",
                    },
                });
            }
            catch
            {
                // servicio inaccesible
            }
        }

        ctx.Snapshot.AddRange(ctx.Snapshot.Persistence, items);
        return Task.FromResult(CollectorResult.Of(items.Count));
    }

    private static string ResolveDisplayName(string? raw, string fallback) =>
        string.IsNullOrEmpty(raw) || raw.StartsWith('@') ? fallback : raw;
}
