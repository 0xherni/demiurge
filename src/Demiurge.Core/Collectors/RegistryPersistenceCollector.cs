using Microsoft.Win32;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-08: persistencia en registro. Run/RunOnce (HKLM/HKCU + WOW6432Node), Winlogon
/// (Userinit, Shell), IFEO Debugger, AppInit_DLLs, hijack de accesibilidad.
/// </summary>
public sealed class RegistryPersistenceCollector : ICollector
{
    public string Id => "COL-08";
    public string Name => "Arranque: registro";
    public int Order => 20;

    private static readonly string[] RunKeys =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    ];

    internal const string DisabledBackupKey = @"SOFTWARE\Demiurge\DisabledStartup";

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var items = new List<PersistenceItem>();

        foreach (var sub in RunKeys)
            ReadRunKey(ctx, items, Registry.LocalMachine, "HKLM", sub);

        foreach (var (_, user, root) in UserProfiles.UserHives())
        {
            using (root)
            {
                foreach (var sub in RunKeys)
                    ReadRunKey(ctx, items, root, $"HKU\\{user}", sub);
                ReadWinlogon(ctx, items, root, $"HKU\\{user}");
            }
        }

        ReadWinlogon(ctx, items, Registry.LocalMachine, "HKLM");
        ReadIfeo(ctx, items, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
        ReadIfeo(ctx, items, @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
        ReadAppInit(ctx, items, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
        ReadAppInit(ctx, items, @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows");

        ctx.Snapshot.AddRange(ctx.Snapshot.Persistence, items);
        return Task.FromResult(CollectorResult.Of(items.Count));
    }

    private static void ReadRunKey(ScanContext ctx, List<PersistenceItem> items, RegistryKey hive, string hiveName, string sub)
    {
        try
        {
            using var key = hive.OpenSubKey(sub);
            if (key is null) return;
            var type = sub.EndsWith("Once", StringComparison.OrdinalIgnoreCase) ? PersistenceType.RunOnce : PersistenceType.RunKey;
            foreach (var name in key.GetValueNames())
            {
                var cmd = key.GetValue(name)?.ToString();
                if (string.IsNullOrWhiteSpace(cmd)) continue;
                items.Add(Build(ctx, type, $"{hiveName}\\{sub}", name, cmd));
            }
        }
        catch
        {
            // clave inaccesible
        }
    }

    private static void ReadWinlogon(ScanContext ctx, List<PersistenceItem> items, RegistryKey hive, string hiveName)
    {
        const string sub = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        try
        {
            using var key = hive.OpenSubKey(sub);
            if (key is null) return;
            foreach (var valueName in new[] { "Userinit", "Shell", "Taskman", "AppSetup" })
            {
                var raw = key.GetValue(valueName)?.ToString();
                if (string.IsNullOrWhiteSpace(raw)) continue;
                // Userinit admite lista separada por comas.
                foreach (var part in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var item = Build(ctx, PersistenceType.Winlogon, $"{hiveName}\\{sub}", valueName, part);
                    item.Extra["value"] = raw;
                    items.Add(item);
                }
            }
        }
        catch
        {
            // ignorar
        }
    }

    private static void ReadIfeo(ScanContext ctx, List<PersistenceItem> items, string sub)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(sub);
            if (key is null) return;
            foreach (var exe in key.GetSubKeyNames())
            {
                using var k = key.OpenSubKey(exe);
                var debugger = k?.GetValue("Debugger")?.ToString();
                if (!string.IsNullOrWhiteSpace(debugger))
                {
                    var item = Build(ctx, PersistenceType.Ifeo, $"HKLM\\{sub}\\{exe}", exe, debugger);
                    item.Extra["target"] = exe;
                    item.Extra["mechanism"] = "Debugger";
                    items.Add(item);
                }
                // GlobalFlag 0x200 + SilentProcessExit\MonitorProcess: otra variante de IFEO.
                if (k?.GetValue("GlobalFlag") is int gf && (gf & 0x200) != 0)
                {
                    using var spe = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{exe}");
                    var monitor = spe?.GetValue("MonitorProcess")?.ToString();
                    if (!string.IsNullOrWhiteSpace(monitor))
                    {
                        var item = Build(ctx, PersistenceType.Ifeo, $"HKLM\\...\\SilentProcessExit\\{exe}", exe, monitor);
                        item.Extra["target"] = exe;
                        item.Extra["mechanism"] = "SilentProcessExit";
                        items.Add(item);
                    }
                }
            }
        }
        catch
        {
            // ignorar
        }
    }

    private static void ReadAppInit(ScanContext ctx, List<PersistenceItem> items, string sub)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(sub);
            var dlls = key?.GetValue("AppInit_DLLs")?.ToString();
            if (string.IsNullOrWhiteSpace(dlls)) return;
            var load = key!.GetValue("LoadAppInit_DLLs") is int l && l != 0;
            foreach (var dll in dlls.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries))
            {
                var item = Build(ctx, PersistenceType.AppInit, $"HKLM\\{sub}", "AppInit_DLLs", dll);
                item.Enabled = load;
                items.Add(item);
            }
        }
        catch
        {
            // ignorar
        }
    }

    internal static PersistenceItem Build(ScanContext ctx, PersistenceType type, string location, string name, string command)
    {
        var r = CommandLineResolver.Resolve(command);
        var target = r.HostedModule ?? r.Executable;
        return new PersistenceItem
        {
            Type = type,
            Location = location,
            Name = name,
            Command = command,
            ResolvedPath = target,
            Arguments = r.Arguments,
            BinaryKey = ctx.Binaries.Register(target),
        };
    }
}
