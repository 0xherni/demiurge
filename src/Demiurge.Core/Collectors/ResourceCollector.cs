using System.Management;
using Demiurge.Core.Model;
using Demiurge.Core.Native;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-26: consumo sostenido de CPU (y GPU en v2) por proceso, medido en una ventana para no
/// reaccionar a picos.
/// </summary>
public sealed class ResourceCollector : ICollector
{
    public string Id => "COL-26";
    public string Name => "Uso de recursos";
    public int Order => 20; // corre en paralelo con el resto (necesita sólo la lista de procesos)

    public async Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.Snapshot.Processes.Where(p => p.Pid > 4).ToList();
        var window = TimeSpan.FromSeconds(Math.Max(5, ctx.Options.ResourceWindowSeconds));
        int cpus = Environment.ProcessorCount;

        var first = new Dictionary<int, long>();
        foreach (var p in processes)
            if (ProcessNative.GetTimes(p.Pid) is { } t) first[p.Pid] = t.kernel100ns + t.user100ns;

        // Muestras intermedias de GPU durante la ventana.
        var gpuSamples = new Dictionary<int, List<double>>();
        var start = DateTime.UtcNow;
        int samples = 0;
        while (DateTime.UtcNow - start < window)
        {
            ct.ThrowIfCancellationRequested();
            if (samples < 4)
            {
                foreach (var (pid, pct) in SampleGpu())
                {
                    if (!gpuSamples.TryGetValue(pid, out var l)) gpuSamples[pid] = l = new();
                    l.Add(pct);
                }
                samples++;
            }
            await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, window.TotalSeconds / 5)), ct).ConfigureAwait(false);
        }
        var elapsed = (DateTime.UtcNow - start).TotalSeconds;

        int measured = 0;
        foreach (var p in processes)
        {
            if (first.TryGetValue(p.Pid, out var t0) && ProcessNative.GetTimes(p.Pid) is { } t1)
            {
                var cpuSeconds = (t1.kernel100ns + t1.user100ns - t0) / 1e7;
                p.CpuPercent = Math.Round(Math.Max(0, cpuSeconds / elapsed / cpus * 100), 1);
                measured++;
            }
            if (gpuSamples.TryGetValue(p.Pid, out var g) && g.Count > 0)
                p.GpuPercent = Math.Round(g.Average(), 1);
        }
        return CollectorResult.Of(measured);
    }

    /// <summary>GPU por proceso desde los contadores "GPU Engine" (pid_XXXX_..._engtype_3D).</summary>
    private static IEnumerable<(int pid, double pct)> SampleGpu()
    {
        var result = new Dictionary<int, double>();
        try
        {
            using var s = new ManagementObjectSearcher(@"root\CIMV2",
                "SELECT Name, UtilizationPercentage FROM Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine");
            foreach (ManagementObject mo in s.Get())
            {
                using (mo)
                {
                    var name = mo["Name"] as string ?? "";
                    int i = name.IndexOf("pid_", StringComparison.Ordinal);
                    if (i < 0) continue;
                    int j = name.IndexOf('_', i + 4);
                    if (j < 0 || !int.TryParse(name.AsSpan(i + 4, j - i - 4), out var pid)) continue;
                    var pct = Convert.ToDouble(mo["UtilizationPercentage"] ?? 0);
                    result[pid] = Math.Max(result.GetValueOrDefault(pid), pct);
                }
            }
        }
        catch
        {
            // sin contadores de GPU (VMs, drivers viejos)
        }
        return result.Select(kv => (kv.Key, kv.Value));
    }
}
