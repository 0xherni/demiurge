using Demiurge.Core.Model;
using Demiurge.Core.Native;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>COL-09: carpetas Startup del usuario (todos los perfiles) y global (ProgramData).</summary>
public sealed class StartupFolderCollector : ICollector
{
    public string Id => "COL-09";
    public string Name => "Arranque: carpetas Inicio";
    public int Order => 20;

    private const string StartupRel = @"Microsoft\Windows\Start Menu\Programs\Startup";

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var items = new List<PersistenceItem>();
        var folders = new List<string>
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), StartupRel),
        };
        folders.AddRange(UserProfiles.All().Select(p => Path.Combine(UserProfiles.RoamingAppData(p), StartupRel)));

        foreach (var folder in folders.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(folder)) continue;
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(folder); }
            catch { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var name = Path.GetFileName(file);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;

                string? target = file;
                string? args = null;
                if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    (target, args) = ShellLink.Resolve(file);

                var r = CommandLineResolver.Resolve(target is null ? null : $"\"{target}\" {args}");
                var resolved = r.HostedModule ?? r.Executable ?? target;
                items.Add(new PersistenceItem
                {
                    Type = PersistenceType.Startup,
                    Location = folder,
                    Name = name,
                    Command = target is null ? file : $"{target} {args}".Trim(),
                    ResolvedPath = resolved,
                    Arguments = args,
                    BinaryKey = ctx.Binaries.Register(resolved),
                    Extra = { ["file"] = file },
                });
            }
        }

        ctx.Snapshot.AddRange(ctx.Snapshot.Persistence, items);
        return Task.FromResult(CollectorResult.Of(items.Count));
    }
}
