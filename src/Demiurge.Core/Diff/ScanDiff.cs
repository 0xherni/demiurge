using Demiurge.Core.Model;
using Demiurge.Core.Text;

namespace Demiurge.Core.Diff;

public sealed class DiffItem
{
    public EntityKind Kind { get; set; }
    public string Key { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>added | removed</summary>
    public string Change { get; set; } = "added";
    public string? Detail { get; set; }
    /// <summary>Si la entidad nueva tiene findings activos en el escaneo actual.</summary>
    public int Score { get; set; }
}

public sealed class DiffReport
{
    public long? PreviousScanId { get; set; }
    public DateTimeOffset? PreviousScanDate { get; set; }
    public string Title { get; set; } = "";
    public List<string> Summary { get; set; } = new();
    public List<DiffItem> Items { get; set; } = new();
}

/// <summary>"Novedades desde el último escaneo": nuevas persistencias, programas, extensiones, cuentas, certificados.</summary>
public static class ScanDiff
{
    private static readonly EntityKind[] Kinds =
    [
        EntityKind.Persistence, EntityKind.InstalledSoftware, EntityKind.Extension, EntityKind.Account,
        EntityKind.Certificate, EntityKind.Driver, EntityKind.BrowserSetting, EntityKind.SystemSetting,
        EntityKind.FirewallRule,
    ];

    public static DiffReport Compute(ScanSnapshot current, ScanSnapshot? previous, TextCatalog text)
    {
        var report = new DiffReport();
        if (previous is null)
        {
            report.Title = text["diff.none"];
            return report;
        }
        report.PreviousScanId = previous.Scan.Id;
        report.PreviousScanDate = previous.Scan.Started;
        report.Title = text.Get("diff.title", ("date", previous.Scan.Started.ToLocalTime().ToString("dddd dd/MM HH:mm", new System.Globalization.CultureInfo("es-AR"))));

        var scoreByEntity = new Dictionary<string, int>();
        foreach (var f in current.Findings.Where(f => f.Weight > 0))
            scoreByEntity[f.EntityKey] = scoreByEntity.GetValueOrDefault(f.EntityKey) + f.Weight;

        foreach (var kind in Kinds)
        {
            var cur = Entities(current, kind).GroupBy(e => e.Key).ToDictionary(g => g.Key, g => g.First());
            var prev = Entities(previous, kind).GroupBy(e => e.Key).ToDictionary(g => g.Key, g => g.First());

            foreach (var (key, e) in cur)
                if (!prev.ContainsKey(key))
                    report.Items.Add(new DiffItem { Kind = kind, Key = key, Name = e.DisplayName, Change = "added", Detail = Detail(e), Score = scoreByEntity.GetValueOrDefault(key) });
            foreach (var (key, e) in prev)
                if (!cur.ContainsKey(key))
                    report.Items.Add(new DiffItem { Kind = kind, Key = key, Name = e.DisplayName, Change = "removed", Detail = Detail(e) });
        }

        foreach (var g in report.Items.Where(i => i.Change == "added").GroupBy(i => i.Kind))
            report.Summary.Add($"Apareció {g.Count()} {text[$"diff.{g.Key}"]}: {string.Join(", ", g.Take(5).Select(i => i.Name))}{(g.Count() > 5 ? "…" : "")}.");
        if (report.Summary.Count == 0) report.Summary.Add(text["diff.none"]);
        return report;
    }

    private static IEnumerable<IEntity> Entities(ScanSnapshot s, EntityKind kind) => kind switch
    {
        EntityKind.Persistence => s.Persistence,
        EntityKind.InstalledSoftware => s.Software,
        EntityKind.Extension => s.Extensions,
        EntityKind.Account => s.Accounts,
        EntityKind.Certificate => s.Certificates,
        EntityKind.Driver => s.Drivers,
        EntityKind.FirewallRule => s.FirewallRules.Where(r => !r.BuiltIn),
        EntityKind.BrowserSetting => s.BrowserSettings,
        // Sólo configuración relevante a infección (hosts, DNS, proxy, exclusiones), no la postura cambiante.
        EntityKind.SystemSetting => s.Settings.Where(x => x.Category == "infection"),
        _ => [],
    };

    private static string? Detail(IEntity e) => e switch
    {
        PersistenceItem p => $"{p.Type}: {p.Command}",
        InstalledSoftware sw => $"{sw.Publisher} {sw.Version}".Trim(),
        BrowserExtension x => $"{x.Browser} ({x.Profile}) · {x.Origin}",
        CertificateInfo c => $"{c.Store} · {c.Issuer}",
        SystemSetting st => $"{st.Name}: {st.Value}",
        BrowserSettingInfo bs => $"{bs.Browser}: {bs.Setting} = {bs.Value}",
        DriverInfo d => d.Path,
        FirewallRule r => $"{r.Action} {r.Direction} {r.App ?? r.LocalPorts}",
        _ => null,
    };
}
