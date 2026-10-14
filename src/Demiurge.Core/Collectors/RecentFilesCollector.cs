using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-25: ejecutables y scripts recientes en Descargas, Escritorio, AppData, Temp, ProgramData y Public,
/// con Mark-of-the-Web (ADS Zone.Identifier). Profundidad y antigüedad limitadas para que sea rápido.
/// </summary>
public sealed class RecentFilesCollector : ICollector
{
    public string Id => "COL-25";
    public string Name => "Archivos recientes";
    public int Order => 20;

    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
        ".lnk", ".msi", ".dll", ".jar", ".iso", ".img", ".vhd", ".vhdx",
    };

    private const int MaxFiles = 5000;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var cutoff = DateTime.Now.AddDays(-ctx.Options.RecentFilesDays);
        int maxDepth = ctx.Options.RecentFilesMaxDepth;
        var roots = new List<(string path, int depth)>
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 1),
            (Path.Combine(Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public"), maxDepth),
            (Path.Combine(PathClassifier.WindowsDir, "Temp"), 1),
        };
        foreach (var p in UserProfiles.All())
        {
            roots.Add((Path.Combine(p.Path, "Downloads"), maxDepth));
            roots.Add((Path.Combine(p.Path, "Desktop"), maxDepth));
            roots.Add((Path.Combine(p.Path, "OneDrive", "Desktop"), maxDepth));
            roots.Add((UserProfiles.RoamingAppData(p), 2));
            roots.Add((Path.Combine(UserProfiles.LocalAppData(p), "Temp"), 2));
            roots.Add((UserProfiles.LocalAppData(p), 1));
        }

        var list = new List<RecentFile>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (root, depth) in roots)
        {
            if (!Directory.Exists(root)) continue;
            Walk(root, depth);
        }

        void Walk(string dir, int depthLeft)
        {
            if (list.Count >= MaxFiles) return;
            ct.ThrowIfCancellationRequested();
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir); }
            catch { return; }
            foreach (var f in files)
            {
                if (list.Count >= MaxFiles) return;
                if (!Extensions.Contains(Path.GetExtension(f)) || !seen.Add(f)) continue;
                FileInfo fi;
                try { fi = new FileInfo(f); } catch { continue; }
                var modified = fi.LastWriteTime;
                var created = fi.CreationTime;
                if (modified < cutoff && created < cutoff) continue;

                var rf = new RecentFile
                {
                    Path = f,
                    Created = created,
                    Modified = modified,
                    Size = fi.Length,
                    DoubleExtension = PathClassifier.HasDoubleExtension(fi.Name),
                };
                ReadMotw(rf);
                // Sólo hasheamos/verificamos lo que vino de internet, tiene doble extensión o es un PE.
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (rf.ZoneId >= 3 || rf.DoubleExtension || ext is ".exe" or ".scr" or ".dll" or ".com" or ".pif")
                    rf.BinaryKey = ctx.Binaries.Register(f);
                list.Add(rf);
            }
            if (depthLeft <= 0) return;
            IEnumerable<string> dirs;
            try { dirs = Directory.EnumerateDirectories(dir); }
            catch { return; }
            foreach (var d in dirs)
            {
                try
                {
                    // No seguir reparse points (junctions de AppData "Application Data", OneDrive placeholders).
                    if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue;
                }
                catch { continue; }
                Walk(d, depthLeft - 1);
            }
        }

        ctx.Snapshot.AddRange(ctx.Snapshot.RecentFiles, list);
        return Task.FromResult(CollectorResult.Of(list.Count));
    }

    private static void ReadMotw(RecentFile rf)
    {
        try
        {
            var ads = rf.Path + ":Zone.Identifier";
            using var fs = new FileStream(ads, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string? line;
            while ((line = sr.ReadLine()) is not null)
            {
                var kv = line.Split('=', 2);
                if (kv.Length != 2) continue;
                switch (kv[0].Trim())
                {
                    case "ZoneId" when int.TryParse(kv[1].Trim(), out var z): rf.ZoneId = z; break;
                    case "HostUrl": rf.HostUrl = kv[1].Trim(); break;
                    case "ReferrerUrl": rf.ReferrerUrl = kv[1].Trim(); break;
                }
            }
        }
        catch
        {
            // sin MotW
        }
    }
}
