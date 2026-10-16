using System.Text;
using System.Text.RegularExpressions;
using Demiurge.Core.Model;
using Demiurge.Core.Native;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-29: comandos que escribió o pegó una persona.
///  - Ejecutar (Win+R): HKCU\...\Explorer\RunMRU (hasta 26, con orden de uso).
///  - Barra de direcciones del Explorador: HKCU\...\Explorer\TypedPaths (sólo lo que parece un comando, no carpetas).
///  - PowerShell: historial de PSReadLine de cada usuario. Por privacidad se guardan sólo las líneas que descargan o
///    ejecutan algo (el resto del historial no sale del disco).
/// Es donde quedan las estafas "ClickFix" y "FileFix": una página falsa le pide a la persona que pegue un comando.
/// </summary>
public sealed class TypedCommandCollector : ICollector
{
    public string Id => "COL-29";
    public string Name => "Comandos escritos";
    public int Order => 20;

    private const int MaxHistoryBytes = 4 * 1024 * 1024;
    private const int MaxHistoryLines = 300;

    /// <summary>Filtro amplio para el historial de PowerShell: la regla H-38 decide después con precisión.</summary>
    private static readonly Regex HistoryPrefilter = new(
        @"https?:|\biex\b|invoke-expression|-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{16,}|frombase64|mshta|certutil|bitsadmin|downloadstring|downloadfile|webclient|\b(iwr|irm|curl|wget)\b|invoke-(webrequest|restmethod)|start-bitstransfer|conhost|\bfinger\b|-w(in(dow)?(style)?)?\s+h",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

    /// <summary>Primer token que hace que una entrada de la barra del Explorador sea un comando y no una carpeta.</summary>
    private static readonly Regex CommandLike = new(
        @"^\s*""?(powershell|pwsh|cmd|mshta|curl|msiexec|rundll32|regsvr32|conhost|wscript|cscript|certutil|bitsadmin|finger|[^\s""]+\.(exe|com|bat|cmd|vbs|js|hta))(\.exe)?""?(\s|$)",
        RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var list = new List<TypedCommand>();
        var warnings = new List<string>();
        var profiles = UserProfiles.All().ToDictionary(p => p.Sid, StringComparer.OrdinalIgnoreCase);

        foreach (var (sid, user, hive) in UserProfiles.UserHives())
        {
            using (hive)
            {
                try
                {
                    list.AddRange(ReadRunMru(hive, user));
                    list.AddRange(ReadTypedPaths(hive, user));
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
                {
                    warnings.Add($"No se pudieron leer los comandos de {user}");
                }
            }
        }

        foreach (var profile in profiles.Values)
        {
            ct.ThrowIfCancellationRequested();
            var dir = Path.Combine(profile.Path, @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine");
            try
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var file in Directory.EnumerateFiles(dir, "*_history.txt"))
                    list.AddRange(ReadPowerShellHistory(file, profile.UserName));
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                warnings.Add($"No se pudo leer el historial de PowerShell de {profile.UserName}");
            }
        }

        // El mismo comando pegado varias veces cuenta una vez.
        var unique = list.GroupBy(c => c.Key).Select(g => g.OrderBy(c => c.Position).First()).ToList();
        ctx.Snapshot.AddRange(ctx.Snapshot.Commands, unique);
        return Task.FromResult(new CollectorResult { ItemCount = unique.Count, Warnings = warnings });
    }

    internal static IEnumerable<TypedCommand> ReadRunMru(Microsoft.Win32.RegistryKey hive, string user)
    {
        using var k = hive.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");
        if (k is null) yield break;
        var order = (k.GetValue("MRUList") as string ?? "").ToCharArray();
        var names = order.Length > 0 ? order.Select(c => c.ToString()) : k.GetValueNames().Where(n => n.Length == 1);
        var when = RegistryNative.LastWrite(k);
        int pos = 0;
        foreach (var name in names)
        {
            if (k.GetValue(name) is not string raw) continue;
            var cmd = CleanRunMru(raw);
            if (cmd.Length == 0) continue;
            yield return new TypedCommand { Source = "run", Command = cmd, User = user, Position = pos, When = pos == 0 ? when : null };
            pos++;
        }
    }

    /// <summary>RunMRU guarda el texto con un sufijo "\1" (o "\\1").</summary>
    internal static string CleanRunMru(string raw)
    {
        var s = raw.TrimEnd('\0');
        if (s.EndsWith(@"\1", StringComparison.Ordinal)) s = s[..^2];
        return s.Trim();
    }

    private static IEnumerable<TypedCommand> ReadTypedPaths(Microsoft.Win32.RegistryKey hive, string user)
    {
        using var k = hive.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths");
        if (k is null) yield break;
        foreach (var name in k.GetValueNames().Where(n => n.StartsWith("url", StringComparison.OrdinalIgnoreCase)))
        {
            if (k.GetValue(name) is not string value || !IsCommandLike(value)) continue;
            int.TryParse(name[3..], out var pos);
            yield return new TypedCommand { Source = "explorer", Command = value.Trim(), User = user, Position = Math.Max(0, pos - 1) };
        }
    }

    internal static bool IsCommandLike(string value) => CommandLike.IsMatch(value);

    private static IEnumerable<TypedCommand> ReadPowerShellHistory(string file, string user)
    {
        var lines = ReadTail(file);
        // Del final hacia atrás: lo más reciente primero.
        int pos = 0, kept = 0;
        for (int i = lines.Count - 1; i >= 0 && kept < MaxHistoryLines; i--, pos++)
        {
            var line = lines[i].Trim();
            if (line.Length < 8 || !MatchesPrefilter(line)) continue;
            kept++;
            yield return new TypedCommand { Source = "powershell", Command = line.Length > 2000 ? line[..2000] : line, User = user, Position = pos };
        }
    }

    internal static bool MatchesPrefilter(string line)
    {
        try { return HistoryPrefilter.IsMatch(line); }
        catch (RegexMatchTimeoutException) { return true; }
    }

    private static List<string> ReadTail(string file)
    {
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (fs.Length > MaxHistoryBytes) fs.Seek(-MaxHistoryBytes, SeekOrigin.End);
        using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var lines = new List<string>();
        if (fs.Position > 0) reader.ReadLine(); // línea cortada
        while (reader.ReadLine() is { } l) lines.Add(l);
        return lines;
    }
}
