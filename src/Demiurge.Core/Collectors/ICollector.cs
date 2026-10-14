using Microsoft.Extensions.Logging;
using Demiurge.Core.Enrichment;
using Demiurge.Core.Model;

namespace Demiurge.Core.Collectors;

public sealed class ScanContext
{
    public required ScanSnapshot Snapshot { get; init; }
    public required DemiurgeOptions Options { get; init; }
    public required BinaryRegistry Binaries { get; init; }
    public required ILogger Logger { get; init; }
    public ScanType ScanType { get; init; } = ScanType.Completo;
    public IProgress<ScanProgress>? Progress { get; init; }
}

public sealed record ScanProgress(string Stage, string? Detail, int Percent);

public sealed class CollectorResult
{
    public int ItemCount { get; init; }
    public List<string> Warnings { get; init; } = new();

    public static CollectorResult Of(int count) => new() { ItemCount = count };
}

/// <summary>
/// Cada colector recolecta un área y emite entidades normalizadas al modelo común (07_Modelo_Datos).
/// </summary>
public interface ICollector
{
    /// <summary>COL-xx</summary>
    string Id { get; }
    string Name { get; }
    /// <summary>Orden relativo: los que alimentan a otros (procesos) van primero.</summary>
    int Order => 100;
    bool EnabledFor(ScanType type) => true;
    Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct);
}
