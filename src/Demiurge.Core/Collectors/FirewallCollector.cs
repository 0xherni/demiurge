using Demiurge.Core.Model;
using Microsoft.Win32;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-28: reglas del Firewall de Windows (almacén local y políticas). El malware suele agregarse una regla
/// para que el firewall lo deje recibir conexiones (RATs, bots).
/// Formato de cada regla en el registro: "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|App=C:\x.exe|Name=...|EmbedCtxt=...|"
/// </summary>
public sealed class FirewallCollector : ICollector
{
    public string Id => "COL-28";
    public string Name => "Reglas del firewall";
    public int Order => 20;

    private static readonly (string Key, string Store)[] Sources =
    [
        (@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", "local"),
        (@"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules", "policy"),
    ];

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var rules = new List<FirewallRule>();
        foreach (var (key, store) in Sources)
        {
            using var k = Registry.LocalMachine.OpenSubKey(key);
            if (k is null) continue;
            foreach (var id in k.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (k.GetValue(id) is not string raw) continue;
                var r = Parse(id, raw, store);
                // Sólo se hashea el programa de reglas que permiten entrar y no son de Windows.
                if (r.Active && r.Action == "Allow" && r.Direction == "In" && !r.BuiltIn && r.App is not null)
                {
                    var app = Environment.ExpandEnvironmentVariables(r.App);
                    if (File.Exists(app)) r.BinaryKey = ctx.Binaries.Register(app);
                }
                rules.Add(r);
            }
        }
        ctx.Snapshot.AddRange(ctx.Snapshot.FirewallRules, rules);
        return Task.FromResult(CollectorResult.Of(rules.Count));
    }

    internal static FirewallRule Parse(string id, string raw, string store)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in raw.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var name = part[..eq];
            var value = part[(eq + 1)..];
            // Claves repetidas (varios LPort, RA4...): se juntan.
            fields[name] = fields.TryGetValue(name, out var prev) ? prev + "," + value : value;
        }
        string? F(string n) => fields.TryGetValue(n, out var v) && v.Length > 0 ? v : null;
        var nameField = F("Name") ?? id;
        var group = F("EmbedCtxt");
        var remote = string.Join(",", new[] { F("RA4"), F("RA6"), F("RA42"), F("RA62") }.Where(x => x is not null));
        return new FirewallRule
        {
            Id = id,
            Name = nameField,
            Action = F("Action") ?? "",
            Direction = F("Dir") ?? "",
            Active = string.Equals(F("Active"), "TRUE", StringComparison.OrdinalIgnoreCase),
            App = F("App"),
            Service = F("Svc"),
            Protocol = F("Protocol"),
            LocalPorts = F("LPort") ?? F("LPort2_10"),
            RemoteAddresses = remote.Length == 0 ? null : remote,
            Profiles = F("Profile"),
            Group = group,
            // Las reglas de Windows referencian recursos ("@FirewallAPI.dll,-25326"); las de apps de la Store usan "@{...}".
            BuiltIn = nameField.StartsWith('@') || (group?.StartsWith('@') ?? false),
            Store = store,
        };
    }
}
