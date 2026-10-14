using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Demiurge.Core.Model;

namespace Demiurge.Core.Collectors;

/// <summary>
/// Ejecuta colectores con timeout individual. Resiliente: si uno falla, los demás siguen y
/// el error queda registrado en el snapshot.
/// </summary>
public sealed class CollectorRunner
{
    private readonly IReadOnlyList<ICollector> _collectors;

    public CollectorRunner(IEnumerable<ICollector> collectors) =>
        _collectors = collectors.OrderBy(c => c.Order).ThenBy(c => c.Id).ToList();

    public IReadOnlyList<ICollector> Collectors => _collectors;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var enabled = _collectors.Where(c => c.EnabledFor(ctx.ScanType)).ToList();
        int done = 0;

        // Los colectores con el mismo Order corren en paralelo; los grupos, en secuencia.
        foreach (var group in enabled.GroupBy(c => c.Order).OrderBy(g => g.Key))
        {
            await Task.WhenAll(group.Select(async c =>
            {
                var status = await RunOneAsync(c, ctx, ct).ConfigureAwait(false);
                ctx.Snapshot.Add(ctx.Snapshot.Collectors, status);
                int n = Interlocked.Increment(ref done);
                ctx.Progress?.Report(new ScanProgress("collect", c.Name, 5 + n * 70 / Math.Max(1, enabled.Count)));
            })).ConfigureAwait(false);
        }
    }

    private static async Task<CollectorStatus> RunOneAsync(ICollector c, ScanContext ctx, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(ctx.Options.CollectorTimeoutSeconds));
        try
        {
            // Task.Run: muchos colectores hacen I/O sincrónico (registro, WMI, COM).
            var work = Task.Run(() => c.CollectAsync(ctx, cts.Token), cts.Token);
            var finished = await Task.WhenAny(work, Task.Delay(Timeout.Infinite, cts.Token)).ConfigureAwait(false);
            if (finished != work)
            {
                ct.ThrowIfCancellationRequested();
                throw new TimeoutException($"Timeout después de {ctx.Options.CollectorTimeoutSeconds}s");
            }
            var result = await work.ConfigureAwait(false);
            foreach (var w in result.Warnings) ctx.Logger.LogWarning("{Collector}: {Warning}", c.Id, w);
            return new CollectorStatus { Id = c.Id, Name = c.Name, Success = true, Duration = sw.Elapsed, ItemCount = result.ItemCount };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            ctx.Logger.LogError(ex, "Colector {Collector} falló", c.Id);
            return new CollectorStatus { Id = c.Id, Name = c.Name, Success = false, Error = ex.Message, Duration = sw.Elapsed };
        }
    }
}
