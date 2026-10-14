using System.Diagnostics;
using System.Management;
using Demiurge.Core.Model;
using Demiurge.Core.Native;

namespace Demiurge.Core.Collectors;

/// <summary>COL-01: snapshot de procesos (System.Diagnostics.Process + WMI Win32_Process).</summary>
public sealed class ProcessCollector : ICollector
{
    public string Id => "COL-01";
    public string Name => "Procesos";
    public int Order => 10;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var byPid = new Dictionary<int, ProcessInfo>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate, SessionId, WorkingSetSize FROM Win32_Process");
            foreach (ManagementObject mo in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                using (mo)
                {
                    int pid = Convert.ToInt32(mo["ProcessId"]);
                    var p = new ProcessInfo
                    {
                        Pid = pid,
                        ParentPid = Convert.ToInt32(mo["ParentProcessId"]),
                        Name = mo["Name"] as string ?? "",
                        Path = mo["ExecutablePath"] as string,
                        CommandLine = mo["CommandLine"] as string,
                        SessionId = Convert.ToInt32(mo["SessionId"] ?? 0),
                        WorkingSetBytes = Convert.ToInt64(mo["WorkingSetSize"] ?? 0L),
                    };
                    if (mo["CreationDate"] is string cd && cd.Length > 0)
                    {
                        try { p.StartTime = ManagementDateTimeConverter.ToDateTime(cd); } catch { /* formato raro */ }
                    }
                    byPid[pid] = p;
                }
            }
        }
        catch (ManagementException)
        {
            // WMI roto: seguimos sólo con System.Diagnostics.Process
        }

        foreach (var proc in Process.GetProcesses())
        {
            using (proc)
            {
                if (!byPid.TryGetValue(proc.Id, out var p))
                {
                    p = new ProcessInfo { Pid = proc.Id, Name = proc.ProcessName + ".exe", SessionId = proc.SessionId };
                    try { p.WorkingSetBytes = proc.WorkingSet64; } catch { }
                    byPid[proc.Id] = p;
                }
            }
        }

        foreach (var p in byPid.Values)
        {
            ct.ThrowIfCancellationRequested();
            if (p.Pid is 0 or 4) { p.Path ??= null; continue; } // Idle / System
            p.Path ??= ProcessNative.GetImagePath(p.Pid);
            var token = ProcessNative.GetTokenData(p.Pid);
            if (token is not null)
            {
                p.User = token.User;
                p.Integrity = token.Integrity;
                p.Elevated = token.Elevated;
            }
            if (p.StartTime is null && ProcessNative.GetTimes(p.Pid) is { } t) p.StartTime = t.created;
            p.BinaryKey = ctx.Binaries.Register(p.Path);
        }

        ctx.Snapshot.AddRange(ctx.Snapshot.Processes, byPid.Values);
        return Task.FromResult(CollectorResult.Of(byPid.Count));
    }
}
