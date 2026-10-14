using System.Management;
using Microsoft.Win32;
using Demiurge.Core.Model;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-18: postura de seguridad (firewall, UAC, SmartScreen, RDP, Windows Update, Secure Boot,
/// BitLocker). Se muestra como "Salud del sistema", nunca como infección.
/// </summary>
public sealed class SecurityPostureCollector : ICollector
{
    public string Id => "COL-18";
    public string Name => "Salud del sistema";
    public int Order => 20;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var s = new List<SystemSetting>();

        foreach (var (profile, label) in new[] { ("DomainProfile", "domain"), ("StandardProfile", "private"), ("PublicProfile", "public") })
        {
            int? policy = ReadInt($@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{profile}", "EnableFirewall");
            int? local = ReadInt($@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}", "EnableFirewall");
            int? v = policy ?? local;
            s.Add(new SystemSetting { Name = $"firewall_{label}", Value = v?.ToString() ?? "?", Expected = "1", Ok = v is null ? null : v == 1 });
        }

        int? lua = ReadInt(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
        int? consent = ReadInt(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin");
        s.Add(new SystemSetting
        {
            Name = "uac",
            Value = lua == 0 ? "desactivado" : consent == 0 ? "sin avisos" : "activado",
            Expected = "activado",
            Ok = lua != 0 && consent != 0,
        });

        var smartScreenPolicy = ReadInt(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen");
        var smartScreen = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")?.GetValue("SmartScreenEnabled")?.ToString();
        bool ssOff = smartScreenPolicy == 0 || string.Equals(smartScreen, "Off", StringComparison.OrdinalIgnoreCase);
        s.Add(new SystemSetting { Name = "smartscreen", Value = ssOff ? "desactivado" : "activado", Expected = "activado", Ok = !ssOff });

        int? deny = ReadInt(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
        int? nla = ReadInt(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
        bool rdpOn = deny == 0;
        s.Add(new SystemSetting
        {
            Name = "rdp",
            Value = rdpOn ? (nla == 1 ? "activado (con NLA)" : "activado (sin NLA)") : "desactivado",
            Expected = "desactivado",
            Ok = !rdpOn,
        });

        bool rebootPending = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") is not null;
        var lastHotfix = LastHotfixDate();
        int? daysSince = lastHotfix is null ? null : (int)(DateTime.Now - lastHotfix.Value).TotalDays;
        s.Add(new SystemSetting
        {
            Name = "windows_update",
            Value = daysSince is null ? "?" : $"última actualización hace {daysSince} días",
            Expected = "≤ 45 días",
            Ok = daysSince is null ? null : daysSince <= 45,
        });
        if (rebootPending)
            s.Add(new SystemSetting { Name = "windows_update_reboot", Value = "reinicio pendiente", Expected = "sin reinicio pendiente", Ok = false });

        int? secureBoot = ReadInt(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
        s.Add(new SystemSetting { Name = "secure_boot", Value = secureBoot?.ToString() ?? "no soportado", Expected = "1", Ok = secureBoot is null ? null : secureBoot == 1 });

        s.Add(BitLocker());

        foreach (var x in s) x.Category = "health";
        ctx.Snapshot.AddRange(ctx.Snapshot.Settings, s);
        return Task.FromResult(CollectorResult.Of(s.Count));
    }

    private static int? ReadInt(string sub, string value)
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(sub);
            return k?.GetValue(value) is int i ? i : null;
        }
        catch
        {
            return null;
        }
    }

    private static DateTime? LastHotfixDate()
    {
        try
        {
            using var s = new ManagementObjectSearcher("SELECT InstalledOn FROM Win32_QuickFixEngineering");
            DateTime? max = null;
            foreach (ManagementObject mo in s.Get())
            {
                using (mo)
                {
                    var raw = mo["InstalledOn"]?.ToString();
                    if (raw is not null && DateTime.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var d) && (max is null || d > max))
                        max = d;
                }
            }
            return max;
        }
        catch
        {
            return null;
        }
    }

    private static SystemSetting BitLocker()
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\CIMV2\Security\MicrosoftVolumeEncryption");
            scope.Connect();
            using var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume"));
            var sys = Path.GetPathRoot(Environment.SystemDirectory)!.TrimEnd('\\');
            foreach (ManagementObject mo in s.Get())
            {
                using (mo)
                {
                    if (!string.Equals(mo["DriveLetter"]?.ToString(), sys, StringComparison.OrdinalIgnoreCase)) continue;
                    var on = Convert.ToUInt32(mo["ProtectionStatus"] ?? 0u) == 1;
                    return new SystemSetting { Name = "bitlocker", Value = on ? "activado" : "desactivado", Expected = "activado", Ok = on };
                }
            }
        }
        catch
        {
            // Windows Home no tiene BitLocker completo
        }
        return new SystemSetting { Name = "bitlocker", Value = "no disponible", Ok = null };
    }
}
