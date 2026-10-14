using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-13 (v2): BITS jobs, paquetes LSA, COM hijacking en HKCU y add-ins de Office.
/// </summary>
public sealed partial class OtherPersistenceCollector : ICollector
{
    public string Id => "COL-13";
    public string Name => "Arranque: otros mecanismos";
    public int Order => 20;

    /// <summary>Paquetes LSA que vienen con Windows.</summary>
    private static readonly HashSet<string> DefaultLsa = new(StringComparer.OrdinalIgnoreCase)
    {
        "", "\"\"", "msv1_0", "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts",
        "livessp", "scecli", "rassfm", "msoidssp",
    };

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var items = new List<PersistenceItem>();
        CollectLsa(ctx, items);
        CollectComHijack(ctx, items, ct);
        CollectOfficeAddins(ctx, items);
        CollectBits(ctx, items);
        ctx.Snapshot.AddRange(ctx.Snapshot.Persistence, items);
        return Task.FromResult(CollectorResult.Of(items.Count));
    }

    private static void CollectLsa(ScanContext ctx, List<PersistenceItem> items)
    {
        using var lsa = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
        if (lsa is null) return;
        foreach (var valueName in new[] { "Security Packages", "Authentication Packages", "Notification Packages" })
        {
            if (lsa.GetValue(valueName) is not string[] packages) continue;
            foreach (var pkg in packages)
            {
                if (DefaultLsa.Contains(pkg.Trim())) continue;
                var dll = CommandLineResolver.Locate(pkg.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? pkg : pkg + ".dll");
                items.Add(new PersistenceItem
                {
                    Type = PersistenceType.Lsa,
                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{valueName}",
                    Name = pkg,
                    Command = pkg,
                    ResolvedPath = dll,
                    BinaryKey = ctx.Binaries.Register(dll),
                });
            }
        }
    }

    /// <summary>CLSID registrados en HKCU que pisan uno de HKLM: así se secuestra un objeto COM sin admin.</summary>
    private static void CollectComHijack(ScanContext ctx, List<PersistenceItem> items, CancellationToken ct)
    {
        foreach (var (_, user, root) in UserProfiles.UserHives())
        {
            using (root)
            {
                using var clsids = root.OpenSubKey(@"Software\Classes\CLSID");
                if (clsids is null) continue;
                foreach (var clsid in clsids.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    using var inproc = clsids.OpenSubKey($@"{clsid}\InprocServer32") ?? clsids.OpenSubKey($@"{clsid}\LocalServer32");
                    var server = inproc?.GetValue(null)?.ToString();
                    if (string.IsNullOrWhiteSpace(server)) continue;
                    using var machine = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}");
                    if (machine is null) continue; // sólo nos interesa cuando pisa un CLSID existente del sistema
                    var r = CommandLineResolver.Resolve(server);
                    items.Add(new PersistenceItem
                    {
                        Type = PersistenceType.ComHijack,
                        Location = $@"HKU\{user}\Software\Classes\CLSID\{clsid}",
                        Name = clsid,
                        Command = server,
                        ResolvedPath = r.Executable,
                        BinaryKey = ctx.Binaries.Register(r.Executable),
                    });
                }
            }
        }
    }

    private static void CollectOfficeAddins(ScanContext ctx, List<PersistenceItem> items)
    {
        string[] apps = ["Word", "Excel", "PowerPoint", "Outlook"];
        void ReadHive(RegistryKey hive, string hiveName)
        {
            foreach (var app in apps)
            {
                foreach (var baseKey in new[] { $@"Software\Microsoft\Office\{app}\Addins", $@"Software\WOW6432Node\Microsoft\Office\{app}\Addins" })
                {
                    using var addins = hive.OpenSubKey(baseKey);
                    if (addins is null) continue;
                    foreach (var progId in addins.GetSubKeyNames())
                    {
                        using var a = addins.OpenSubKey(progId);
                        int load = a?.GetValue("LoadBehavior") is int lb ? lb : 0;
                        string? path = null;
                        using (var clsidKey = Registry.ClassesRoot.OpenSubKey($@"{progId}\CLSID"))
                        {
                            var clsid = clsidKey?.GetValue(null)?.ToString();
                            if (clsid is not null) path = ScheduledTaskCollector.ResolveClsid(clsid);
                        }
                        path ??= a?.GetValue("Manifest")?.ToString()?.Split('|')[0];
                        items.Add(new PersistenceItem
                        {
                            Type = PersistenceType.OfficeAddin,
                            Location = $@"{hiveName}\{baseKey}",
                            Name = progId,
                            Command = a?.GetValue("FriendlyName")?.ToString() ?? progId,
                            ResolvedPath = path,
                            Enabled = (load & 1) == 1 || load == 3,
                            BinaryKey = path is not null && !path.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? ctx.Binaries.Register(path) : null,
                            Extra = { ["app"] = app, ["loadBehavior"] = load.ToString() },
                        });
                    }
                }
            }
        }

        ReadHive(Registry.LocalMachine, "HKLM");
        foreach (var (_, user, root) in UserProfiles.UserHives())
            using (root) ReadHive(root, $"HKU\\{user}");

        // Carpetas de inicio de Word/Excel (plantillas que se cargan solas).
        foreach (var p in UserProfiles.All())
        {
            foreach (var dir in new[] { @"Microsoft\Word\STARTUP", @"Microsoft\Excel\XLSTART" })
            {
                var full = Path.Combine(UserProfiles.RoamingAppData(p), dir);
                if (!Directory.Exists(full)) continue;
                foreach (var f in Directory.EnumerateFiles(full))
                {
                    items.Add(new PersistenceItem
                    {
                        Type = PersistenceType.OfficeAddin,
                        Location = full,
                        Name = Path.GetFileName(f),
                        Command = f,
                        ResolvedPath = f,
                        BinaryKey = ctx.Binaries.Register(f),
                    });
                }
            }
        }
    }

    [GeneratedRegex(@"GUID:\s*(\{[^}]+\})\s+DISPLAY:\s*'?(?<name>[^'\r\n]*)'?", RegexOptions.IgnoreCase)]
    private static partial Regex BitsJobHeader();

    [GeneratedRegex(@"NOTIFICATION COMMAND LINE:\s*(?<cmd>.+)", RegexOptions.IgnoreCase)]
    private static partial Regex BitsNotify();

    /// <summary>
    /// BITS: un job con "notification command line" ejecuta un programa al terminar la descarga.
    /// Se lee con bitsadmin (presente en todas las versiones de Windows).
    /// </summary>
    private static void CollectBits(ScanContext ctx, List<PersistenceItem> items)
    {
        var bitsadmin = Path.Combine(PathClassifier.System32Dir, "bitsadmin.exe");
        if (!File.Exists(bitsadmin)) return;
        try
        {
            var psi = new ProcessStartInfo(bitsadmin, "/list /allusers /verbose")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(30000);

            var jobs = output.Split("GUID:", StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(s => "GUID:" + s);
            foreach (var job in jobs)
            {
                var header = BitsJobHeader().Match(job);
                var notify = BitsNotify().Match(job);
                if (!notify.Success) continue;
                var cmd = notify.Groups["cmd"].Value.Trim();
                if (cmd.Equals("none", StringComparison.OrdinalIgnoreCase) || cmd.Length == 0) continue;
                var r = CommandLineResolver.Resolve(cmd.Trim('\''));
                items.Add(new PersistenceItem
                {
                    Type = PersistenceType.Bits,
                    Location = "BITS " + (header.Success ? header.Groups[1].Value : "?"),
                    Name = header.Success ? header.Groups["name"].Value : "BITS job",
                    Command = cmd,
                    ResolvedPath = r.Executable,
                    BinaryKey = ctx.Binaries.Register(r.Executable),
                });
            }
        }
        catch
        {
            // bitsadmin falló
        }
    }
}
