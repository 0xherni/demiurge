using System.Text.Json;
using System.Text.Json.Nodes;
using Demiurge.Core;
using Demiurge.Core.Ipc;
using Demiurge.Core.Native;
using Microsoft.Extensions.Logging;

namespace Demiurge.Cli;

/// <summary>El motor dentro del mismo proceso (no hay servicio): la CLI es una herramienta de desarrollo y diagnóstico.</summary>
public sealed class LocalClient : IAsyncDisposable
{
    public event Action<string, JsonNode?>? EventReceived;

    public LocalClient(ILogger logger)
    {
        Engine = new DemiurgeEngine(logger);
        Engine.Push += (e, d) => EventReceived?.Invoke(e, d);
        Engine.Start();
    }

    public DemiurgeEngine Engine { get; }

    public async Task<JsonNode?> CallAsync(string op, object? args = null, TimeSpan? timeout = null)
    {
        var req = new IpcRequest { Op = op, Args = args is null ? null : JsonSerializer.SerializeToNode(args, Protocol.Json) as JsonObject };
        return await Engine.HandleAsync(req, CallerInfo.Self(), CancellationToken.None);
    }

    public ValueTask DisposeAsync() => Engine.DisposeAsync();
}
