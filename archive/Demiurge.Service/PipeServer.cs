using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Demiurge.Core.Ipc;
using Demiurge.Core.Native;

namespace Demiurge.Service;

/// <summary>
/// Servidor del named pipe.
///  - ACL: sólo usuarios con sesión interactiva local, SYSTEM y administradores; acceso por red denegado.
///  - Cada conexión se identifica por el PID que informa el kernel y el token de ese proceso. Sin elevación sólo
///    se puede consultar el estado (ver Protocol.PublicOperations); el resto lo autoriza DemiurgeEngine.
///  - La primera instancia se crea con FirstPipeInstance: si otro proceso ocupó el nombre antes que el servicio
///    (para hacerse pasar por él), el servicio lo detecta y lo registra en vez de convivir con el impostor.
///  - Límite de conexiones simultáneas y de tamaño de mensaje (evita agotar memoria del servicio).
/// </summary>
public sealed class PipeServer : BackgroundService
{
    private const int MaxInstances = 16;

    private readonly EngineHost _host;
    private readonly ILogger<PipeServer> _logger;
    private readonly ConcurrentDictionary<Guid, Connection> _clients = new();

    private sealed class Connection(NamedPipeServerStream pipe, CallerInfo caller)
    {
        public NamedPipeServerStream Pipe { get; } = pipe;
        public CallerInfo Caller { get; } = caller;
        public StreamWriter Writer { get; } = new(pipe, new UTF8Encoding(false)) { AutoFlush = true };
        public SemaphoreSlim WriteLock { get; } = new(1);
    }

    public PipeServer(EngineHost host, ILogger<PipeServer> logger)
    {
        _host = host;
        _logger = logger;
        _host.Engine.Push += Broadcast;
    }

    private static PipeSecurity CreateSecurity()
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        return sec;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        bool first = true;
        _logger.LogInformation("Escuchando en \\\\.\\pipe\\{Pipe}", Protocol.PipeName);
        while (!stoppingToken.IsCancellationRequested)
        {
            if (_clients.Count >= MaxInstances - 1)
            {
                await Task.Delay(250, stoppingToken);
                continue;
            }
            NamedPipeServerStream pipe;
            try
            {
                var options = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : 0);
                pipe = NamedPipeServerStreamAcl.Create(Protocol.PipeName, PipeDirection.InOut, MaxInstances,
                    PipeTransmissionMode.Byte, options, 64 * 1024, 64 * 1024, CreateSecurity());
                first = false;
                await pipe.WaitForConnectionAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (UnauthorizedAccessException) when (first)
            {
                _logger.LogCritical("Otro proceso ya ocupa el pipe {Pipe}: posible intento de suplantar a Demiurge. Reintentando…", Protocol.PipeName);
                await Task.Delay(5000, stoppingToken);
                continue;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creando el pipe");
                await Task.Delay(1000, stoppingToken);
                continue;
            }
            var caller = CallerInfo.FromPid(PipeNative.ClientPid(pipe.SafePipeHandle));
            _ = Task.Run(() => HandleClientAsync(pipe, caller, stoppingToken), stoppingToken);
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CallerInfo caller, CancellationToken ct)
    {
        var id = Guid.NewGuid();
        var conn = new Connection(pipe, caller);
        _clients[id] = conn;
        _logger.LogDebug("Cliente conectado: {Image} (PID {Pid}, {User}, elevado: {Elevated})", caller.Image, caller.Pid, caller.User, caller.Elevated);
        try
        {
            using var reader = new StreamReader(pipe, new UTF8Encoding(false));
            string? line;
            while (!ct.IsCancellationRequested && (line = await ReadBoundedLineAsync(reader, ct)) is not null)
            {
                IpcRequest? req = null;
                IpcResponse resp;
                try
                {
                    req = JsonSerializer.Deserialize<IpcRequest>(line, Protocol.Json) ?? throw new InvalidDataException("Request vacío");
                    var data = await _host.Engine.HandleAsync(req, caller, ct);
                    resp = new IpcResponse { Id = req.Id, Ok = true, Data = data };
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning("Request {Op} falló: {Error}", req?.Op, ex.Message);
                    resp = new IpcResponse { Id = req?.Id, Ok = false, Error = ex.Message };
                }
                await SendAsync(conn, resp);
            }
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Se cortó la conexión de PID {Pid}: {Error}", caller.Pid, ex.Message);
        }
        catch (IOException)
        {
            // cliente desconectado
        }
        catch (OperationCanceledException)
        {
            // apagando
        }
        finally
        {
            _clients.TryRemove(id, out _);
            await pipe.DisposeAsync();
        }
    }

    /// <summary>Lee una línea sin cargar en memoria más de Protocol.MaxMessageChars.</summary>
    private static async Task<string?> ReadBoundedLineAsync(StreamReader reader, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var buf = new char[1];
        while (true)
        {
            int n = await reader.ReadAsync(buf.AsMemory(), ct);
            if (n == 0) return sb.Length == 0 ? null : sb.ToString();
            if (buf[0] == '\n') return sb.ToString().TrimEnd('\r');
            sb.Append(buf[0]);
            if (sb.Length > Protocol.MaxMessageChars) throw new InvalidDataException("Mensaje demasiado grande");
        }
    }

    private static async Task SendAsync(Connection c, IpcResponse resp)
    {
        var json = JsonSerializer.Serialize(resp, Protocol.Json);
        await c.WriteLock.WaitAsync();
        try { await c.Writer.WriteLineAsync(json); }
        finally { c.WriteLock.Release(); }
    }

    private void Broadcast(string evt, JsonNode? data)
    {
        foreach (var c in _clients.Values)
        {
            _ = Task.Run(async () =>
            {
                try { await SendAsync(c, new IpcResponse { Event = evt, Ok = true, Data = data?.DeepClone() }); }
                catch { /* cliente caído */ }
            });
        }
    }
}
