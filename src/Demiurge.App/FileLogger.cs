using System.IO;
using Demiurge.Core.Util;
using Microsoft.Extensions.Logging;

namespace Demiurge.App;

/// <summary>Log a %ProgramData%\Demiurge\logs\demiurge.log con rotación simple (5 MB).</summary>
public sealed class FileLogger : ILogger
{
    private static readonly object Lock = new();
    private readonly string _path = Path.Combine(DemiurgePaths.Logs, "demiurge.log");

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel)) return;
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{logLevel}] {formatter(state, exception)}{(exception is null ? "" : " | " + exception)}";
        lock (Lock)
        {
            try
            {
                var fi = new FileInfo(_path);
                if (fi.Exists && fi.Length > 5 * 1024 * 1024) File.Move(_path, _path + ".1", overwrite: true);
                File.AppendAllText(_path, line + Environment.NewLine);
            }
            catch
            {
                // el log nunca tumba la app
            }
        }
    }
}
