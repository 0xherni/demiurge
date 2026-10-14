using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Demiurge.Core;
using Demiurge.Core.Ipc;

namespace Demiurge.Cli;

/// <summary>Transporte común: servicio por named pipe o motor en el mismo proceso (modo --local).</summary>
public interface IDemiurgeClient : IAsyncDisposable
{
    event Action<string, JsonNode?>? EventReceived;
    Task<JsonNode?> CallAsync(string op, object? args = null, TimeSpan? timeout = null);
}

public sealed class ServiceClient : IDemiurgeClient
{
    private readonly PipeClient _pipe = new();

    public event Action<string, JsonNode?>? EventReceived
    {
        add => _pipe.EventReceived += value;
        remove => _pipe.EventReceived -= value;
    }

    public static async Task<ServiceClient?> TryConnectAsync()
    {
        var c = new ServiceClient();
        try
        {
            await c._pipe.ConnectAsync(TimeSpan.FromSeconds(2));
            return c;
        }
        catch (TimeoutException)
        {
            await c.DisposeAsync();
            return null;
        }
    }

    public Task<JsonNode?> CallAsync(string op, object? args = null, TimeSpan? timeout = null) => _pipe.CallAsync(op, args, timeout);

    public ValueTask DisposeAsync() => _pipe.DisposeAsync();
}

/// <summary>Motor en el mismo proceso: útil para desarrollo o si el servicio no está instalado.</summary>
public sealed class LocalClient : IDemiurgeClient
{
    private readonly DemiurgeEngine _engine;

    public event Action<string, JsonNode?>? EventReceived;

    public LocalClient(ILogger logger)
    {
        _engine = new DemiurgeEngine(logger, enableLive: false);
        _engine.Push += (e, d) => EventReceived?.Invoke(e, d);
        _engine.Start();
    }

    public DemiurgeEngine Engine => _engine;

    public async Task<JsonNode?> CallAsync(string op, object? args = null, TimeSpan? timeout = null)
    {
        var req = new IpcRequest { Op = op, Args = args is null ? null : JsonSerializer.SerializeToNode(args, Protocol.Json) as JsonObject };
        return await _engine.HandleAsync(req, Demiurge.Core.Native.CallerInfo.Self(), CancellationToken.None);
    }

    public ValueTask DisposeAsync() => _engine.DisposeAsync();
}
