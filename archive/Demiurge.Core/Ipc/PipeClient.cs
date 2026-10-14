using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Demiurge.Core.Ipc;

/// <summary>Cliente del named pipe para la App, la CLI y el servidor MCP.</summary>
public sealed class PipeClient : IAsyncDisposable
{
    private readonly NamedPipeClientStream _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private readonly ConcurrentDictionary<string, TaskCompletionSource<IpcResponse>> _pending = new();
    private readonly SemaphoreSlim _writeLock = new(1);
    private Task? _readLoop;

    /// <summary>Eventos push del servicio (progreso de escaneo, alertas del modo vivo).</summary>
    public event Action<string, JsonNode?>? EventReceived;

    public PipeClient(string pipeName = Protocol.PipeName) =>
        _pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

    public async Task ConnectAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        await _pipe.ConnectAsync((int)timeout.TotalMilliseconds, ct).ConfigureAwait(false);
        VerifyServer();
        _reader = new StreamReader(_pipe, new UTF8Encoding(false));
        _writer = new StreamWriter(_pipe, new UTF8Encoding(false)) { AutoFlush = true };
        _readLoop = Task.Run(ReadLoopAsync, ct);
    }

    /// <summary>
    /// Anti-suplantación: un programa sin privilegios podría crear el pipe antes que el servicio y mostrar un veredicto
    /// falso ("tu PC está limpia"). El servidor legítimo corre como SYSTEM (o, en desarrollo, como admin elevado).
    /// Si podemos leer el token del servidor y NO está elevado, es un impostor. Si no lo podemos leer, es porque es un
    /// proceso privilegiado de otro usuario (SYSTEM): un usuario común no puede abrir ese token.
    /// </summary>
    private void VerifyServer()
    {
        var pid = Native.PipeNative.ServerPid(_pipe.SafePipeHandle)
                  ?? throw new IOException("No se pudo identificar al servidor del pipe.");
        var token = Native.ProcessNative.GetTokenData(pid);
        if (token is not null && !token.Elevated)
        {
            _pipe.Dispose();
            throw new System.Security.SecurityException(
                $"El servidor de Demiurge (PID {pid}, {Native.ProcessNative.GetImagePath(pid)}) no es el servicio legítimo: corre sin privilegios. Posible suplantación.");
        }
    }

    private async Task ReadLoopAsync()
    {
        try
        {
            string? line;
            while ((line = await _reader!.ReadLineAsync().ConfigureAwait(false)) is not null)
            {
                var msg = JsonSerializer.Deserialize<IpcResponse>(line, Protocol.Json);
                if (msg is null) continue;
                if (msg.Event is not null) EventReceived?.Invoke(msg.Event, msg.Data);
                else if (msg.Id is not null && _pending.TryRemove(msg.Id, out var tcs)) tcs.TrySetResult(msg);
            }
        }
        catch (IOException)
        {
            // pipe cerrado
        }
        foreach (var p in _pending.Values) p.TrySetException(new IOException("Se cerró la conexión con el servicio Demiurge."));
    }

    public async Task<JsonNode?> CallAsync(string op, object? args = null, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var req = new IpcRequest { Op = op, Args = args is null ? null : JsonSerializer.SerializeToNode(args, Protocol.Json) as JsonObject };
        var tcs = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[req.Id] = tcs;
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try { await _writer!.WriteLineAsync(JsonSerializer.Serialize(req, Protocol.Json).AsMemory(), ct).ConfigureAwait(false); }
        finally { _writeLock.Release(); }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout ?? TimeSpan.FromMinutes(2));
        await using var reg = cts.Token.Register(() => tcs.TrySetCanceled());
        var resp = await tcs.Task.ConfigureAwait(false);
        if (!resp.Ok) throw new InvalidOperationException(resp.Error ?? "Error del servicio");
        return resp.Data;
    }

    public async ValueTask DisposeAsync()
    {
        await _pipe.DisposeAsync().ConfigureAwait(false);
        if (_readLoop is not null) try { await _readLoop.ConfigureAwait(false); } catch { }
    }
}
