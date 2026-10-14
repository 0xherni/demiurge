using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;
using Demiurge.Core.Enrichment;
using Demiurge.Core.Util;

namespace Demiurge.Core.External;

/// <summary>
/// Ejecuta herramientas externas como procesos separados (nunca se linkea código GPL) y verifica el
/// hash del binario antes de ejecutarlo.
/// </summary>
public sealed class ExternalRunner
{
    private readonly ILogger _logger;

    public ExternalRunner(ILogger logger) => _logger = logger;

    public sealed record Result(int ExitCode, string StdOut, string StdErr, bool TimedOut);

    /// <summary>
    /// Busca el ejecutable: primero la copia que viene con el instalador (Program Files\Demiurge\tools, sólo
    /// administradores escriben ahí), después una ruta explícita y por último %ProgramData%\Demiurge\tools.
    /// </summary>
    public static string? ResolvePath(ExternalToolOptions tool)
    {
        if (BundledPath(tool) is { } bundled) return bundled;
        if (!string.IsNullOrEmpty(tool.Path)) return File.Exists(tool.Path) ? tool.Path : null;
        var candidate = Path.Combine(DemiurgePaths.Tools, tool.FileName);
        if (File.Exists(candidate)) return candidate;
        // Subcarpetas (los zips suelen extraerse con carpeta propia).
        return Directory.EnumerateFiles(DemiurgePaths.Tools, tool.FileName, SearchOption.AllDirectories).FirstOrDefault();
    }

    private static string? BundledPath(ExternalToolOptions tool)
    {
        var entry = ToolLock.Get(tool.LockId);
        if (entry is null) return null;
        var p = Path.Combine(AppContext.BaseDirectory, "tools", entry.Dir, entry.Exe);
        return File.Exists(p) ? p : null;
    }

    /// <summary>
    /// Verifica que el binario exista, lo haya puesto un administrador y coincida con el SHA256 esperado:
    /// el del archivo de bloqueo (tools.lock.json) para las herramientas incluidas, o el fijado por el usuario.
    /// </summary>
    public string? Verify(ExternalToolOptions tool, out string? error)
    {
        error = null;
        if (!tool.Enabled) { error = "deshabilitada en la configuración"; return null; }
        var path = ResolvePath(tool);
        if (path is null) { error = $"no se encontró {tool.FileName}"; return null; }
        if (!Security.DataDirectoryLockdown.CanTrust(path))
        {
            error = $"{path} no lo puso un administrador; por seguridad no se ejecuta";
            return null;
        }
        var expected = path == BundledPath(tool) ? ToolLock.Get(tool.LockId)?.ExeSha256 : tool.ExpectedSha256;
        if (string.IsNullOrWhiteSpace(expected))
        {
            error = $"falta fijar el SHA256 esperado de {tool.FileName} (demiurge tools pin)";
            return null;
        }
        var actual = FileHasher.Compute(path)?.Sha256;
        if (!string.Equals(actual, expected.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            error = $"el hash de {path} no coincide con el esperado (¿binario reemplazado?)";
            return null;
        }
        return path;
    }

    public async Task<Result> RunAsync(string exe, IEnumerable<string> args, TimeSpan timeout, CancellationToken ct, string? workingDir = null)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            WorkingDirectory = workingDir ?? Path.GetDirectoryName(exe)!,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var p = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        p.OutputDataReceived += (_, e) => { if (e.Data is not null) lock (stdout) stdout.AppendLine(e.Data); };
        p.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (stderr) stderr.AppendLine(e.Data); };
        p.Start();
        try { p.PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        bool timedOut = false;
        try
        {
            await p.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            timedOut = !ct.IsCancellationRequested;
            try { p.Kill(entireProcessTree: true); } catch { }
            if (!timedOut) throw;
            _logger.LogWarning("{Exe} superó el timeout de {Timeout}", Path.GetFileName(exe), timeout);
        }
        return new Result(timedOut ? -1 : p.ExitCode, stdout.ToString(), stderr.ToString(), timedOut);
    }
}
