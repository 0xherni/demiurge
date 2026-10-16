using System.Collections.Concurrent;
using System.IO;
using Demiurge.Core.Util;
using Microsoft.Extensions.Logging;

namespace Demiurge.App;

/// <summary>
/// Log a %ProgramData%\Demiurge\logs\demiurge.log con rotación simple (5 MB).
/// Hasta que la carpeta de datos está protegida no se escribe nada: se guarda en memoria y se vuelca después. Si no,
/// una carpeta plantada por otro usuario (o un enlace) haría que la app elevada escriba o mueva archivos donde él quiera.
/// </summary>
public sealed class FileLogger : ILogger
{
    private static readonly object Lock = new();
    private readonly ConcurrentQueue<string> _pending = new();

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel)) return;
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{logLevel}] {formatter(state, exception)}{(exception is null ? "" : " | " + exception)}";
        if (!DemiurgePaths.Secured)
        {
            if (_pending.Count < 1000) _pending.Enqueue(line);
            return;
        }
        lock (Lock)
        {
            try
            {
                var path = Path.Combine(DemiurgePaths.Logs, "demiurge.log");
                var fi = new FileInfo(path);
                if (fi.Exists && fi.Length > 5 * 1024 * 1024) File.Move(path, path + ".1", overwrite: true);
                var lines = new List<string>();
                while (_pending.TryDequeue(out var p)) lines.Add(p);
                lines.Add(line);
                File.AppendAllLines(path, lines);
            }
            catch
            {
                // el log nunca tumba la app
            }
        }
    }
}
