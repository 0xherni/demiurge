using Microsoft.Extensions.Logging.EventLog;
using Demiurge.Core.Util;
using Demiurge.Service;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(o => o.ServiceName = "DemiurgeService");
builder.Logging.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss "; });
builder.Logging.AddProvider(new FileLoggerProvider(Path.Combine(DemiurgePaths.Logs, "demiurge-service.log")));
if (OperatingSystem.IsWindows())
    builder.Logging.AddEventLog(new EventLogSettings { SourceName = "Demiurge", LogName = "Application" });

builder.Services.AddSingleton<EngineHost>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<EngineHost>());
builder.Services.AddHostedService<PipeServer>();

var host = builder.Build();
host.Run();
