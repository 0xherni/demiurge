using System.Windows;
using System.Windows.Threading;
using Demiurge.Core;
using Microsoft.Extensions.Logging;

namespace Demiurge.App;

public partial class App : Application
{
    private Mutex? _single;

    public static DemiurgeEngine Engine { get; private set; } = null!;
    public static ILogger Log { get; } = new FileLogger();

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Una sola instancia: dos motores escribiendo la misma base no tiene sentido.
        _single = new Mutex(true, @"Global\Demiurge.App", out bool first);
        if (!first)
        {
            MessageBox.Show("Demiurge ya está abierto.", "Demiurge", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandled;
        AppDomain.CurrentDomain.UnhandledException += (_, a) => Log.LogCritical(a.ExceptionObject as Exception, "Error no controlado");
        TaskScheduler.UnobservedTaskException += (_, a) => { Log.LogError(a.Exception, "Tarea con error"); a.SetObserved(); };

        try
        {
            // Protege la carpeta de datos, carga reglas, KnowledgeBase y feeds.
            Engine = new DemiurgeEngine(Log);
            Engine.Start();
        }
        catch (Exception ex)
        {
            Log.LogCritical(ex, "No se pudo iniciar el motor");
            MessageBox.Show($"No se pudo iniciar Demiurge:\n\n{ex.Message}", "Demiurge", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        // Feeds de inteligencia: se actualizan al abrir si están vencidos (sin bloquear la ventana; offline usa la última copia).
        _ = Task.Run(async () =>
        {
            try { await Engine.UpdateFeedsAsync(force: false, CancellationToken.None); }
            catch (Exception ex) { Log.LogWarning(ex, "No se pudieron actualizar los feeds"); }
        });

        new MainWindow().Show();
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log.LogError(e.Exception, "Error en la interfaz");
        MessageBox.Show($"Ocurrió un error inesperado:\n\n{e.Exception.Message}\n\nQuedó registrado en el log.", "Demiurge", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Al cerrar no queda nada: se libera el motor y termina el proceso.
        try { Engine?.DisposeAsync().AsTask().Wait(2000); } catch { }
        _single?.Dispose();
        base.OnExit(e);
    }
}
