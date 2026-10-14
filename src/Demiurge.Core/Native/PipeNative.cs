using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Demiurge.Core.Native;

/// <summary>Identidad del otro extremo de un named pipe (la da el kernel; no se puede falsificar desde el cliente).</summary>
public static class PipeNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);

    public static int? ClientPid(SafePipeHandle h) => GetNamedPipeClientProcessId(h, out var pid) ? (int)pid : null;
    public static int? ServerPid(SafePipeHandle h) => GetNamedPipeServerProcessId(h, out var pid) ? (int)pid : null;
}

/// <summary>Quién hace el pedido al servicio.</summary>
public sealed record CallerInfo(int? Pid, string? User, bool Elevated, string? Image, bool InProcess = false)
{
    /// <summary>
    /// El propio proceso (la app o la CLI con el motor adentro). No hay límite de privilegios que proteger:
    /// un proceso no puede escalar llamándose a sí mismo, y el motor actúa con los permisos que ya tiene.
    /// </summary>
    public static CallerInfo Self() =>
        new(Environment.ProcessId, Environment.UserName, ProcessNative.IsAdministrator(), Environment.ProcessPath, InProcess: true);

    public static CallerInfo FromPid(int? pid)
    {
        if (pid is null) return new(null, null, false, null);
        var token = ProcessNative.GetTokenData(pid.Value);
        return new(pid, token?.User, token?.Elevated == true, ProcessNative.GetImagePath(pid.Value));
    }
}
