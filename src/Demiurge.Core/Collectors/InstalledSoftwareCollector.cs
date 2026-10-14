using System.Globalization;
using Microsoft.Win32;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>COL-21: programas instalados (Uninstall en HKLM, HKCU y WOW6432Node).</summary>
public sealed class InstalledSoftwareCollector : ICollector
{
    public string Id => "COL-21";
    public string Name => "Programas instalados";
    public int Order => 20;

    private const string Uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string UninstallWow = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var byKey = new Dictionary<string, InstalledSoftware>(StringComparer.OrdinalIgnoreCase);

        void Read(RegistryKey hive, string sub, string scope)
        {
            using var root = hive.OpenSubKey(sub);
            if (root is null) return;
            foreach (var name in root.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var k = root.OpenSubKey(name);
                if (k is null) continue;
                var display = k.GetValue("DisplayName")?.ToString();
                if (string.IsNullOrWhiteSpace(display)) continue;
                if (k.GetValue("SystemComponent") is int sc && sc == 1) continue;
                if (k.GetValue("ParentKeyName") is not null) continue; // actualizaciones/parches

                var sw = new InstalledSoftware
                {
                    Name = display.Trim(),
                    Publisher = k.GetValue("Publisher")?.ToString()?.Trim(),
                    Version = k.GetValue("DisplayVersion")?.ToString(),
                    InstallLocation = k.GetValue("InstallLocation")?.ToString(),
                    UninstallString = k.GetValue("UninstallString")?.ToString(),
                    Scope = scope,
                };
                if (k.GetValue("InstallDate")?.ToString() is { Length: 8 } d &&
                    DateTime.TryParseExact(d, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
                    sw.InstallDate = dt;
                byKey.TryAdd(sw.Key, sw);
            }
        }

        Read(Registry.LocalMachine, Uninstall, "machine");
        Read(Registry.LocalMachine, UninstallWow, "machine");
        foreach (var (_, user, root) in UserProfiles.UserHives())
        {
            using (root)
            {
                Read(root, Uninstall, user);
                Read(root, UninstallWow, user);
            }
        }

        ctx.Snapshot.AddRange(ctx.Snapshot.Software, byKey.Values);
        return Task.FromResult(CollectorResult.Of(byKey.Count));
    }
}
