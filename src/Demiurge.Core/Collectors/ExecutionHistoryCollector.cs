using System.Globalization;
using Demiurge.Core.Model;
using Demiurge.Core.Native;
using Demiurge.Core.Util;
using Microsoft.Win32;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-27: historial de ejecución. Windows deja rastros de lo que se ejecutó aunque el programa ya no exista:
///  - BAM (Background Activity Moderator): ruta completa + última ejecución, por usuario.
///  - UserAssist: programas abiertos desde el Explorador (ruta, cantidad de veces, última vez), por usuario. Nombres en ROT13.
///  - PCA (Program Compatibility Assistant): en Windows 11, %windir%\appcompat\pca\PcaAppLaunchDic.txt con ruta y fecha;
///    en Windows 10, el registro Compatibility Assistant\Store con rutas.
///  - Prefetch: %windir%\Prefetch\NOMBRE.EXE-HASH.pf (sólo nombre; las fechas del archivo aproximan primera/última ejecución).
/// Es clave para ver infecciones que ya pasaron: un ladrón de contraseñas típico corre una vez y se borra.
/// </summary>
public sealed class ExecutionHistoryCollector : ICollector
{
    public string Id => "COL-27";
    public string Name => "Historial de ejecución";
    public int Order => 20;

    private const string UserAssistExe = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";
    private const string UserAssistLnk = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}";

    /// <summary>KNOWNFOLDERID que UserAssist usa como prefijo de las rutas.</summary>
    private static readonly Dictionary<string, Func<string>> KnownFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        ["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"] = () => Environment.GetFolderPath(Environment.SpecialFolder.System),
        ["{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}"] = () => Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
        ["{F38BF404-1D43-42F2-9305-67DE0B28FC23}"] = () => Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        ["{6D809377-6AF0-444B-8957-A3773F02200E}"] = () => Environment.GetEnvironmentVariable("ProgramW6432") ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        ["{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"] = () => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
    };

    /// <summary>Carpetas por usuario (se resuelven con la ruta del perfil, porque el servicio no es ese usuario).</summary>
    private static readonly Dictionary<string, string> UserKnownFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        ["{374DE290-123F-4565-9164-39C4925E467B}"] = "Downloads",
        ["{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"] = "Desktop",
        ["{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"] = "Documents",
        ["{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"] = @"AppData\Roaming",
        ["{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}"] = @"AppData\Local",
        ["{A520A1A4-1780-4FF6-BD18-167343C5AF16}"] = @"AppData\LocalLow",
    };

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var since = DateTimeOffset.Now.AddDays(-ctx.Options.ExecutionHistoryDays);
        var byPath = new Dictionary<string, ExecutionRecord>(StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>();
        var profiles = UserProfiles.All().ToDictionary(p => p.Sid, StringComparer.OrdinalIgnoreCase);

        void Add(string path, string source, DateTimeOffset? last, int? count, string? user)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            path = path.Trim();
            if (last is not null && last < since) return;
            if (!byPath.TryGetValue(path, out var r))
                byPath[path] = r = new ExecutionRecord { Path = path, Name = Path.GetFileName(path) };
            if (!r.Sources.Contains(source)) r.Sources.Add(source);
            if (last is not null && (r.LastRun is null || last > r.LastRun)) r.LastRun = last;
            if (count is not null) r.RunCount = Math.Max(r.RunCount ?? 0, count.Value);
            r.User ??= user;
        }

        // ---- BAM ----
        foreach (var root in new[] { @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", @"SYSTEM\CurrentControlSet\Services\bam\UserSettings" })
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(root);
                if (k is null) continue;
                foreach (var sid in k.GetSubKeyNames())
                {
                    using var u = k.OpenSubKey(sid);
                    if (u is null) continue;
                    var user = profiles.TryGetValue(sid, out var p) ? p.UserName : sid;
                    foreach (var name in u.GetValueNames())
                    {
                        if (!name.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) continue; // apps de la Store, etc.
                        if (u.GetValue(name) is not byte[] data || data.Length < 8) continue;
                        Add(DevicePath.ToDosPath(name), "BAM", FileTime(BitConverter.ToInt64(data, 0)), null, user);
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
                warnings.Add("BAM requiere permisos de administrador");
            }
        }

        // ---- UserAssist y PCA (Windows 10) por usuario ----
        foreach (var (sid, user, hive) in UserProfiles.UserHives())
        {
            using (hive)
            {
                profiles.TryGetValue(sid, out var profile);
                foreach (var guid in new[] { UserAssistExe, UserAssistLnk })
                {
                    using var count = hive.OpenSubKey($@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count");
                    if (count is null) continue;
                    foreach (var encoded in count.GetValueNames())
                    {
                        var decoded = Rot13(encoded);
                        if (guid == UserAssistLnk || !decoded.Contains('\\')) continue; // accesos directos y entradas internas (UEME_*)
                        var path = ResolveUserAssistPath(decoded, profile);
                        if (path is null || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                        DateTimeOffset? last = null;
                        int? runs = null;
                        if (count.GetValue(encoded) is byte[] d && d.Length >= 68)
                        {
                            runs = BitConverter.ToInt32(d, 4);
                            last = FileTime(BitConverter.ToInt64(d, 60));
                        }
                        Add(path, "UserAssist", last, runs, user);
                    }
                }

                using var pca = hive.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store");
                if (pca is not null)
                    foreach (var path in pca.GetValueNames().Where(v => v.Length > 3 && v[1] == ':'))
                        Add(path, "PCA", null, null, user);
            }
        }

        // ---- PCA (Windows 11 22H2+) ----
        var pcaFile = Path.Combine(PathClassifier.WindowsDir, @"appcompat\pca\PcaAppLaunchDic.txt");
        try
        {
            if (File.Exists(pcaFile))
            {
                foreach (var line in File.ReadLines(pcaFile, System.Text.Encoding.Unicode))
                {
                    var parts = line.Split('|');
                    if (parts.Length < 2) continue;
                    DateTimeOffset? when = DateTime.TryParse(parts[1], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dt) ? dt : null;
                    Add(parts[0], "PCA", when, null, null);
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            warnings.Add("PcaAppLaunchDic.txt no se pudo leer");
        }

        // ---- Prefetch (sólo nombre) ----
        var prefetchOnly = new List<ExecutionRecord>();
        try
        {
            var dir = Path.Combine(PathClassifier.WindowsDir, "Prefetch");
            if (Directory.Exists(dir))
            {
                foreach (var pf in Directory.EnumerateFiles(dir, "*.pf"))
                {
                    var fi = new FileInfo(pf);
                    if (fi.LastWriteTime < since) continue;
                    var name = Path.GetFileNameWithoutExtension(pf);
                    var dash = name.LastIndexOf('-');
                    if (dash > 0) name = name[..dash];
                    var match = byPath.Values.FirstOrDefault(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                    if (match is not null)
                    {
                        if (!match.Sources.Contains("Prefetch")) match.Sources.Add("Prefetch");
                        match.FirstRun ??= fi.CreationTime;
                        if (match.LastRun is null || fi.LastWriteTime > match.LastRun) match.LastRun = fi.LastWriteTime;
                    }
                    else
                    {
                        prefetchOnly.Add(new ExecutionRecord { Name = name, Sources = ["Prefetch"], FirstRun = fi.CreationTime, LastRun = fi.LastWriteTime });
                    }
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            warnings.Add("Prefetch requiere permisos de administrador");
        }

        // Estado actual: ¿el archivo sigue ahí? Se registra el binario (hash, firma) sólo fuera de Windows: lo de System32 lo firma Microsoft.
        foreach (var r in byPath.Values)
        {
            ct.ThrowIfCancellationRequested();
            try { r.Exists = File.Exists(r.Path); } catch { r.Exists = null; }
            if (r.Exists == true && !PathClassifier.IsInWindowsDir(r.Path))
                r.BinaryKey = ctx.Binaries.Register(r.Path);
        }

        var all = byPath.Values.Concat(prefetchOnly).ToList();
        ctx.Snapshot.AddRange(ctx.Snapshot.Executions, all);
        return Task.FromResult(new CollectorResult { ItemCount = all.Count, Warnings = warnings.Distinct().ToList() });
    }

    private static DateTimeOffset? FileTime(long ft)
    {
        if (ft <= 0) return null;
        try { return DateTimeOffset.FromFileTime(ft); } catch { return null; }
    }

    internal static string Rot13(string s) => new(s.Select(c =>
        c is >= 'a' and <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
        c is >= 'A' and <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());

    private static string? ResolveUserAssistPath(string decoded, UserProfiles.Profile? profile)
    {
        if (decoded.Length > 2 && decoded[1] == ':') return decoded;
        if (!decoded.StartsWith('{')) return null;
        var end = decoded.IndexOf('}');
        if (end < 0) return null;
        var guid = decoded[..(end + 1)];
        var rest = decoded[(end + 1)..].TrimStart('\\');
        if (KnownFolders.TryGetValue(guid, out var folder)) return Path.Combine(folder(), rest);
        if (profile is not null && UserKnownFolders.TryGetValue(guid, out var rel)) return Path.Combine(profile.Path, rel, rest);
        return null;
    }
}
