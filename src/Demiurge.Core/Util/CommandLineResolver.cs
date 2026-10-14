namespace Demiurge.Core.Util;

/// <summary>
/// Resuelve el ejecutable real detrás de un comando de persistencia (COL-08):
/// comillas, argumentos, variables de entorno, "rundll32 X,Y", rutas sin extensión, etc.
/// </summary>
public static class CommandLineResolver
{
    private static readonly string[] Hosts = ["rundll32.exe", "rundll32", "regsvr32.exe", "regsvr32"];
    private static readonly string[] ExeExtensions = [".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll", ".scr", ".hta", ".lnk"];

    public sealed record Resolved(string? Executable, string? Arguments, string? HostedModule);

    public static Resolved Resolve(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return new(null, null, null);
        var cmd = Environment.ExpandEnvironmentVariables(command.Trim()).Replace("\\??\\", "");
        if (cmd.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), cmd[12..]);
        if (cmd.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase))
            cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), cmd);

        string exe;
        string args;
        if (cmd.StartsWith('"'))
        {
            int end = cmd.IndexOf('"', 1);
            exe = end > 0 ? cmd[1..end] : cmd.Trim('"');
            args = end > 0 && end + 1 < cmd.Length ? cmd[(end + 1)..].Trim() : "";
        }
        else
        {
            (exe, args) = SplitUnquoted(cmd);
        }

        exe = Locate(exe) ?? exe;

        string? hosted = null;
        var name = Path.GetFileName(exe);
        if (Hosts.Any(h => name.Equals(h, StringComparison.OrdinalIgnoreCase)) && args.Length > 0)
        {
            // rundll32 "C:\x\a.dll",Entry  |  regsvr32 /s C:\x\a.dll
            var a = args;
            while (a.StartsWith('/') || a.StartsWith('-'))
            {
                int sp = a.IndexOf(' ');
                if (sp < 0) { a = ""; break; }
                a = a[(sp + 1)..].TrimStart();
            }
            if (a.StartsWith('"'))
            {
                int end = a.IndexOf('"', 1);
                hosted = end > 0 ? a[1..end] : a.Trim('"');
            }
            else
            {
                int comma = a.IndexOf(',');
                int space = a.IndexOf(' ');
                int cut = new[] { comma, space }.Where(i => i >= 0).DefaultIfEmpty(a.Length).Min();
                hosted = a[..cut];
            }
            hosted = string.IsNullOrWhiteSpace(hosted) ? null : Locate(hosted) ?? hosted;
        }

        return new(exe, string.IsNullOrEmpty(args) ? null : args, hosted);
    }

    /// <summary>Sin comillas: probar prefijos crecientes hasta encontrar un archivo existente (C:\Program Files\x y.exe -a).</summary>
    private static (string exe, string args) SplitUnquoted(string cmd)
    {
        var parts = cmd.Split(' ');
        for (int i = 1; i <= parts.Length; i++)
        {
            var candidate = string.Join(' ', parts.Take(i));
            if (LooksLikeFile(candidate) && Locate(candidate) is not null)
                return (candidate, string.Join(' ', parts.Skip(i)).Trim());
        }
        // Cortar en la primera extensión ejecutable conocida.
        var lower = cmd.ToLowerInvariant();
        foreach (var ext in ExeExtensions)
        {
            int idx = lower.IndexOf(ext + " ", StringComparison.Ordinal);
            if (idx > 0) return (cmd[..(idx + ext.Length)], cmd[(idx + ext.Length)..].Trim());
            if (lower.EndsWith(ext)) return (cmd, "");
        }
        int sp = cmd.IndexOf(' ');
        return sp > 0 ? (cmd[..sp], cmd[(sp + 1)..]) : (cmd, "");
    }

    private static bool LooksLikeFile(string s) => s.Length > 0 && !s.EndsWith(' ');

    public static string? Locate(string candidate)
    {
        try
        {
            candidate = candidate.Trim().Trim('"');
            if (candidate.Length == 0) return null;
            if (Path.IsPathRooted(candidate))
            {
                if (File.Exists(candidate)) return candidate;
                if (!Path.HasExtension(candidate) && File.Exists(candidate + ".exe")) return candidate + ".exe";
                return null;
            }
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var dirs = new List<string> { Path.Combine(win, "System32"), win, Path.Combine(win, "System32", "WindowsPowerShell", "v1.0") };
            dirs.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries));
            foreach (var d in dirs)
            {
                var p = Path.Combine(d, candidate);
                if (File.Exists(p)) return p;
                if (!Path.HasExtension(candidate) && File.Exists(p + ".exe")) return p + ".exe";
            }
        }
        catch
        {
            // path inválido
        }
        return null;
    }
}
