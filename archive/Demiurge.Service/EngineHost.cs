using Demiurge.Core;

namespace Demiurge.Service;

/// <summary>
/// Mantiene vivo el motor: modo vivo (ETW), actualización periódica de feeds y escaneo inicial.
/// </summary>
public sealed class EngineHost : BackgroundService
{
    private readonly ILogger<EngineHost> _logger;

    public DemiurgeEngine Engine { get; }

    public EngineHost(ILogger<EngineHost> logger)
    {
        _logger = logger;
        Engine = new DemiurgeEngine(logger, enableLive: true);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Engine.Start();
        _logger.LogInformation("Demiurge {Version} iniciado", ScanOrchestrator.AppVersion);

        // Feeds al iniciar y cada N horas (offline: se usa la última copia).
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Engine.UpdateFeedsAsync(force: false, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Actualización de feeds falló");
            }

            // Primer escaneo automático si nunca se escaneó (para que la App tenga algo que mostrar).
            if (Engine.Latest is null && !Engine.Orchestrator.IsScanning)
            {
                try { await Engine.ScanAsync(Core.Model.ScanType.Completo, stoppingToken); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogError(ex, "Escaneo inicial falló"); }
            }

            try { await Task.Delay(TimeSpan.FromHours(Math.Max(1, Engine.Options.FeedUpdateHours)), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        await Engine.DisposeAsync();
    }
}
