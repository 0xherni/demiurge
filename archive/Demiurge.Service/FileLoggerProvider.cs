namespace Demiurge.Service;

/// <summary>Log a archivo con rotación simple (5 MB), para diagnóstico sin depender del Visor de eventos.</summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly string _path;
    private readonly object _lock = new();

    public FileLoggerProvider(string path) => _path = path;

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    public void Dispose() { }

    internal void Write(string line)
    {
        lock (_lock)
        {
            try
            {
                var fi = new FileInfo(_path);
                if (fi.Exists && fi.Length > 5 * 1024 * 1024)
                    File.Move(_path, _path + ".1", overwrite: true);
                File.AppendAllText(_path, line + Environment.NewLine);
            }
            catch
            {
                // no romper el servicio por el log
            }
        }
    }

    private sealed class FileLogger(FileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            var cat = category[(category.LastIndexOf('.') + 1)..];
            provider.Write($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{logLevel}] {cat}: {formatter(state, exception)}{(exception is null ? "" : " | " + exception)}");
        }
    }
}
