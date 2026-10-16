using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>COL-15: archivo hosts, servidores DNS por adaptador, proxy WinINET (por usuario) y WinHTTP.</summary>
public sealed class NetworkConfigCollector : ICollector
{
    public string Id => "COL-15";
    public string Name => "Configuración de red";
    public int Order => 20;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var settings = new List<SystemSetting>();

        // Hosts
        var hostsPath = Path.Combine(PathClassifier.System32Dir, @"drivers\etc\hosts");
        var hostsEntries = new List<string>();
        try
        {
            foreach (var raw in File.ReadLines(hostsPath))
            {
                var line = raw.Split('#')[0].Trim();
                if (line.Length == 0) continue;
                hostsEntries.Add(line);
            }
        }
        catch
        {
            // sin acceso al hosts
        }
        ctx.Snapshot.AddRange(ctx.Snapshot.HostsEntries, hostsEntries);
        foreach (var entry in hostsEntries)
            settings.Add(new SystemSetting { Name = "hosts", Value = entry, Category = "infection" });

        // DNS y gateway por adaptador. Distinguimos DNS fijado a mano (lo que hace el malware) de DHCP.
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            IPInterfaceProperties props;
            try { props = nic.GetIPProperties(); } catch { continue; }
            var gateways = props.GatewayAddresses.Select(g => g.Address.ToString()).ToList();
            var staticDns = StaticNameServers(nic.Id);
            foreach (var dns in props.DnsAddresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork || !a.IsIPv6SiteLocal))
            {
                var value = dns.ToString().Split('%')[0];
                settings.Add(new SystemSetting
                {
                    Name = "dns",
                    Value = value,
                    Category = "infection",
                    Source = staticDns.Contains(value) ? "static" : "dhcp",
                    Detail = $"{nic.Name}; gateway: {string.Join(", ", gateways)}",
                });
            }
        }

        // Proxy WinINET por usuario
        foreach (var (_, user, root) in UserProfiles.UserHives())
        {
            using (root)
            {
                using var k = root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                if (k is null) continue;
                bool enabled = k.GetValue("ProxyEnable") is int pe && pe != 0;
                var server = k.GetValue("ProxyServer")?.ToString();
                var pac = k.GetValue("AutoConfigURL")?.ToString();
                if (enabled && !string.IsNullOrWhiteSpace(server))
                    settings.Add(new SystemSetting { Name = "proxy", Value = server, Category = "infection", Detail = $"WinINET ({user}); bypass: {k.GetValue("ProxyOverride")}" });
                if (!string.IsNullOrWhiteSpace(pac))
                    settings.Add(new SystemSetting { Name = "proxy_pac", Value = pac, Category = "infection", Detail = $"WinINET ({user})" });
            }
        }

        // Proxy WinHTTP
        var winhttp = ReadWinHttpProxy();
        if (winhttp is not null)
            settings.Add(new SystemSetting { Name = "proxy", Value = winhttp, Category = "infection", Detail = "WinHTTP (sistema)" });

        ctx.Snapshot.AddRange(ctx.Snapshot.Settings, settings);
        return Task.FromResult(CollectorResult.Of(settings.Count));
    }

    private static HashSet<string> StaticNameServers(string interfaceId)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in new[] { @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces" })
        {
            try
            {
                using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"{root}\{interfaceId}");
                var ns = k?.GetValue("NameServer")?.ToString();
                if (string.IsNullOrWhiteSpace(ns)) continue;
                foreach (var s in ns.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries)) set.Add(s);
            }
            catch
            {
                // ignorar
            }
        }
        return set;
    }

    private static string? ReadWinHttpProxy()
    {
        try
        {
            var psi = new ProcessStartInfo(Path.Combine(PathClassifier.System32Dir, "netsh.exe"), "winhttp show proxy")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return null;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10000);
            // "Direct access (no proxy server)." / "Acceso directo (sin servidor proxy)."
            if (output.Contains("Direct access", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Acceso directo", StringComparison.OrdinalIgnoreCase))
                return null;
            var line = output.Split('\n').FirstOrDefault(l => l.Contains("Proxy Server", StringComparison.OrdinalIgnoreCase) || l.Contains("Servidor", StringComparison.OrdinalIgnoreCase));
            return line?.Split(':', 2).ElementAtOrDefault(1)?.Trim();
        }
        catch
        {
            return null;
        }
    }
}
