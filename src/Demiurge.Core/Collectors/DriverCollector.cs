using System.Management;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>COL-24 (v2): drivers (WMI Win32_SystemDriver) con firma y hash.</summary>
public sealed class DriverCollector : ICollector
{
    public string Id => "COL-24";
    public string Name => "Controladores";
    public int Order => 20;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var list = new List<DriverInfo>();
        using var s = new ManagementObjectSearcher("SELECT Name, DisplayName, PathName, State, StartMode FROM Win32_SystemDriver");
        foreach (ManagementObject mo in s.Get())
        {
            ct.ThrowIfCancellationRequested();
            using (mo)
            {
                var state = mo["State"]?.ToString();
                var path = CommandLineResolver.Resolve(mo["PathName"]?.ToString()).Executable;
                var d = new DriverInfo
                {
                    Name = mo["Name"]?.ToString() ?? "",
                    DisplayName2 = mo["DisplayName"]?.ToString(),
                    Path = path,
                    State = state,
                    StartMode = mo["StartMode"]?.ToString(),
                };
                // Hasheamos/verificamos sólo los cargados o de arranque automático (los demás son miles de inbox drivers).
                if (state == "Running" || d.StartMode is "Boot" or "System" or "Auto")
                    d.BinaryKey = ctx.Binaries.Register(path);
                list.Add(d);
            }
        }
        ctx.Snapshot.AddRange(ctx.Snapshot.Drivers, list);
        return Task.FromResult(CollectorResult.Of(list.Count));
    }
}
