using System.Globalization;
using Demiurge.Core.Model;
using Demiurge.Core.Storage;
using Demiurge.Core.Util;

namespace Demiurge.Core.Story;

public sealed class TimelineEvent
{
    public DateTimeOffset? Time { get; set; }
    /// <summary>download | file | run | command | startup | event | install | account | defender | action | change</summary>
    public string Kind { get; set; } = "";
    public string Title { get; set; } = "";
    public string? Detail { get; set; }
    /// <summary>danger | review | question | info | ok</summary>
    public string Level { get; set; } = "info";
    /// <summary>Tarjeta a la que lleva (clave de scoring).</summary>
    public string? EntityKey { get; set; }
    /// <summary>
    /// Identidad comprobada: eventos con el mismo hilo son EL MISMO archivo (misma ruta o mismo binario). Es la única
    /// relación que la línea de tiempo afirma; que dos cosas pasen cerca no se presenta como causa.
    /// </summary>
    public string? Thread { get; set; }
    public string? ThreadLabel { get; set; }
}

public sealed class TimelineEpisode
{
    public DateTimeOffset Start { get; set; }
    public DateTimeOffset End { get; set; }
    public string Title { get; set; } = "";
    public List<TimelineEvent> Events { get; set; } = new();
}

public sealed class Timeline
{
    public List<TimelineEpisode> Episodes { get; set; } = new();
    /// <summary>Cosas relacionadas para las que Windows no guarda fecha (arranque, extensiones, comandos de PowerShell).</summary>
    public List<TimelineEvent> Undated { get; set; } = new();
    public string Note { get; set; } = "";
}

/// <summary>
/// "Qué pasó": ordena por fecha lo que Windows registró sobre las tarjetas que hay que revisar, y lo agrupa en
/// momentos (eventos separados por menos de 3 horas). No es inteligencia artificial ni adivina causas: sólo junta
/// fechas reales y marca cuando dos eventos son el mismo archivo.
/// </summary>
public static class TimelineBuilder
{
    private static readonly TimeSpan EpisodeGap = TimeSpan.FromHours(3);
    private static readonly CultureInfo Es = new("es-AR");

    public static Timeline Build(ScanSnapshot s, IReadOnlyList<ActionRecord> actions, int days = 30)
    {
        var since = DateTimeOffset.Now.AddDays(-days);
        var events = new List<TimelineEvent>();
        var flagged = s.Scores.Where(x => x.Level != EntityLevel.Info || x.PendingQuestion is not null).ToList();
        var findingsBy = s.Findings.GroupBy(f => f.ScoringKey).ToDictionary(g => g.Key, g => g.ToList());

        foreach (var sc in flagged)
        {
            var level = Level(sc);
            var bin = s.GetBinary(sc.ScoringKey);
            if (bin is not null) AddBinaryEvents(s, bin, sc.ScoringKey, level, events);

            foreach (var f in findingsBy.GetValueOrDefault(sc.ScoringKey) ?? [])
            {
                if (f.Weight <= 0 && f.Question is null) continue;
                AddFindingEvents(s, f, sc.ScoringKey, level, events);
            }
        }

        foreach (var d in s.Defender.Detections.Where(d => d.Time is not null))
        {
            var paths = Rules.Heuristics.DefenderFilePaths(d).ToList();
            bool present = paths.Any(File.Exists);
            events.Add(new TimelineEvent
            {
                Time = d.Time, Kind = "defender", Level = present ? "danger" : "info",
                Title = $"Microsoft Defender detectó {d.ThreatName}",
                Detail = present ? "El archivo sigue en la PC." : "Defender lo resolvió.",
                Thread = paths.Count == 1 ? paths[0].ToLowerInvariant() : null, ThreadLabel = paths.Count == 1 ? Path.GetFileName(paths[0]) : null,
            });
        }

        foreach (var a in actions.Where(a => !a.Reverted && a.Type != "allowlist"))
            events.Add(new TimelineEvent { Time = a.Date, Kind = "action", Level = "ok", Title = "Usaste Demiurge", Detail = a.Description });

        // Mismo hecho visto por dos lados (ej. la ejecución que vieron BAM y la tarjeta del binario): una vez.
        var unique = events
            .GroupBy(e => (e.Title, Minute: e.Time?.ToUnixTimeSeconds() / 60, e.Thread))
            .Select(g => g.OrderBy(e => Rank(e.Level)).First())
            .ToList();

        var timeline = new Timeline
        {
            Note = "Ordenamos por fecha lo que Windows registró. Que dos cosas pasen cerca no prueba que una causó la otra; cuando sabemos que se trata del mismo archivo, lo marcamos.",
        };
        timeline.Undated = unique.Where(e => e.Time is null).OrderBy(e => Rank(e.Level)).Take(60).ToList();

        var dated = unique.Where(e => e.Time is not null && e.Time >= since).OrderBy(e => e.Time).ToList();
        if (dated.Count > 300) dated = dated.Skip(dated.Count - 300).ToList();
        TimelineEpisode? current = null;
        foreach (var e in dated)
        {
            if (current is null || e.Time!.Value - current.End > EpisodeGap)
            {
                current = new TimelineEpisode { Start = e.Time!.Value, End = e.Time.Value };
                timeline.Episodes.Add(current);
            }
            current.Events.Add(e);
            current.End = e.Time!.Value;
        }
        foreach (var ep in timeline.Episodes) ep.Title = EpisodeTitle(ep);
        // Lo más reciente primero; dentro de cada momento, en el orden en que pasó.
        timeline.Episodes.Reverse();
        return timeline;
    }

    private static void AddBinaryEvents(ScanSnapshot s, BinaryInfo bin, string scoringKey, string level, List<TimelineEvent> events)
    {
        var thread = bin.Path.ToLowerInvariant();
        var label = Path.GetFileName(bin.Path);
        var folder = PathClassifier.UserWritableFolder(bin.Path) ?? Path.GetDirectoryName(bin.Path);

        var download = s.RecentFiles.FirstOrDefault(r => r.BinaryKey == bin.Key || r.Path.Equals(bin.Path, StringComparison.OrdinalIgnoreCase));
        if (download?.HostUrl is not null)
            events.Add(Ev(download.Created, "download", $"Se descargó {label}", $"Desde {Host(download.HostUrl)}", level, scoringKey, thread, label));
        else if (bin.Created is not null)
            events.Add(Ev(bin.Created, "file", $"Apareció {label}", $"En {folder}", level, scoringKey, thread, label));

        foreach (var x in s.Executions.Where(x => x.BinaryKey == bin.Key || (x.Path is not null && x.Path.Equals(bin.Path, StringComparison.OrdinalIgnoreCase))))
            AddExecution(x, scoringKey, level, events);

        foreach (var p in s.Processes.Where(p => p.BinaryKey == bin.Key && p.StartTime is not null))
            events.Add(Ev(p.StartTime, "run", $"Se abrió {label}", p.EndTime is null ? "Seguía abierto al momento del escaneo." : null, level, scoringKey, thread, label));

        foreach (var p in s.Persistence.Where(p => p.BinaryKey == bin.Key))
            events.Add(Ev(null, "startup", $"{label} quedó configurado para arrancar solo", Inventory.InventoryBuilder.TypeLabel(p.Type), level, scoringKey, thread, label));
    }

    private static void AddExecution(ExecutionRecord x, string scoringKey, string level, List<TimelineEvent> events)
    {
        var thread = (x.Path ?? x.Name).ToLowerInvariant();
        var gone = x.Exists == false ? " Ya no está en el disco." : "";
        var folder = PathClassifier.UserWritableFolder(x.Path) ?? (x.Path is null ? null : Path.GetDirectoryName(x.Path));
        if (x.LastRun is not null)
            events.Add(Ev(x.LastRun, "run", $"Se ejecutó {x.Name}", (folder is null ? "" : $"Desde {folder}.") + gone, level, scoringKey, thread, x.Name));
        if (x.FirstRun is not null && (x.LastRun is null || (x.LastRun.Value - x.FirstRun.Value).Duration() > TimeSpan.FromMinutes(1)))
            events.Add(Ev(x.FirstRun, "run", $"{x.Name} se ejecutó por primera vez", (folder is null ? "" : $"Desde {folder}.") + gone, level, scoringKey, thread, x.Name));
    }

    private static void AddFindingEvents(ScanSnapshot s, Finding f, string scoringKey, string level, List<TimelineEvent> events)
    {
        switch (f.EntityKind)
        {
            case EntityKind.Execution:
                foreach (var x in s.Executions.Where(x => x.Key == f.EntityKey)) AddExecution(x, scoringKey, level, events);
                break;
            case EntityKind.TypedCommand:
                foreach (var c in s.Commands.Where(c => c.Key == f.EntityKey))
                {
                    var where = c.Source switch { "run" => "en Ejecutar (Win+R)", "explorer" => "en la barra del Explorador", _ => "en PowerShell" };
                    events.Add(Ev(c.When, "command", $"Se pegó un comando {where}", c.DisplayName, level, scoringKey, null, null));
                }
                break;
            case EntityKind.AppIntegrity:
                foreach (var a in s.AppIntegrity.Where(a => a.Key == f.EntityKey))
                    events.Add(Ev(a.Modified, "change", $"Se modificó el archivo de arranque de {a.App}", "Le agregaron código que no es de la aplicación.", level, scoringKey, a.Path.ToLowerInvariant(), "index.js"));
                break;
            case EntityKind.RecentFile:
                foreach (var r in s.RecentFiles.Where(r => r.Key == f.EntityKey))
                {
                    var label = Path.GetFileName(r.Path);
                    events.Add(Ev(r.Created, r.HostUrl is null ? "file" : "download", r.HostUrl is null ? $"Apareció {label}" : $"Se descargó {label}",
                        r.HostUrl is null ? $"En {PathClassifier.UserWritableFolder(r.Path) ?? Path.GetDirectoryName(r.Path)}" : $"Desde {Host(r.HostUrl)}", level, scoringKey, r.Path.ToLowerInvariant(), label));
                }
                break;
            case EntityKind.Event:
                foreach (var e in s.Events.Where(e => e.Key == f.EntityKey))
                    events.Add(Ev(e.Timestamp, "event", f.HeuristicName, Short(f.Explanation), level, scoringKey, null, null));
                break;
            case EntityKind.Account:
                foreach (var a in s.Accounts.Where(a => a.Key == f.EntityKey))
                    events.Add(Ev(a.Created, "account", $"Se creó la cuenta \"{a.Name}\"", a.IsAdmin ? "Con permisos de administrador." : null, level, scoringKey, null, null));
                break;
            case EntityKind.InstalledSoftware:
                foreach (var sw in s.Software.Where(x => x.Key == f.EntityKey))
                    events.Add(Ev(sw.InstallDate, "install", $"Se instaló {sw.Name}", sw.Publisher, level, scoringKey, null, null));
                break;
            case EntityKind.Persistence:
                foreach (var p in s.Persistence.Where(p => p.Key == f.EntityKey && p.BinaryKey is null))
                    events.Add(Ev(null, "startup", $"\"{p.DisplayName}\" quedó configurado para arrancar solo", Inventory.InventoryBuilder.TypeLabel(p.Type), level, scoringKey, null, null));
                break;
            case EntityKind.Extension:
                foreach (var x in s.Extensions.Where(x => x.Key == f.EntityKey))
                    events.Add(Ev(null, "install", $"Extensión \"{x.Name}\" en {x.Browser}", f.HeuristicName, level, scoringKey, null, null));
                break;
            case EntityKind.Certificate or EntityKind.SystemSetting or EntityKind.BrowserSetting or EntityKind.FirewallRule or EntityKind.Driver:
                events.Add(Ev(null, "change", f.HeuristicName, Short(f.Explanation), level, scoringKey, null, null));
                break;
        }

        // Hayabusa: la regla trae la fecha de la última vez que se vio.
        if (f.HeuristicId == "H-31")
        {
            var rule = f.RawData["rule"]?.ToString();
            var det = s.ExternalDetections.FirstOrDefault(d => d.Tool == "EXT-03" && d.Rule == rule);
            if (det is not null && DateTimeOffset.TryParse(det.Data.GetValueOrDefault("last"), CultureInfo.InvariantCulture, DateTimeStyles.None, out var last))
                events.Add(Ev(last, "event", $"Registro de Windows: {rule}", det.Data.GetValueOrDefault("count") is { } c && c != "1" ? $"Se vio {c} veces." : null, level, scoringKey, null, null));
        }
    }

    private static TimelineEvent Ev(DateTimeOffset? time, string kind, string title, string? detail, string level, string scoringKey, string? thread, string? threadLabel) => new()
    {
        Time = time, Kind = kind, Title = title, Detail = string.IsNullOrWhiteSpace(detail) ? null : detail.Trim(), Level = level,
        EntityKey = scoringKey, Thread = thread, ThreadLabel = threadLabel,
    };

    private static string Level(EntityScore sc) =>
        sc.Level == EntityLevel.Peligroso ? "danger" : sc.Level == EntityLevel.Revisar ? "review" : sc.PendingQuestion is not null ? "question" : "info";

    private static int Rank(string level) => level switch { "danger" => 0, "review" => 1, "question" => 2, "info" => 3, _ => 4 };

    private static string Host(string url) => Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.Host : url;

    private static string Short(string s) => s.Length > 200 ? s[..197] + "…" : s;

    private static string EpisodeTitle(TimelineEpisode ep)
    {
        var start = ep.Start.ToLocalTime();
        var end = ep.End.ToLocalTime();
        var day = start.ToString("dddd d 'de' MMMM", Es);
        day = char.ToUpper(day[0], Es) + day[1..];
        if (end - start < TimeSpan.FromMinutes(2)) return $"{day}, {start:HH:mm}";
        return start.Date == end.Date ? $"{day}, de {start:HH:mm} a {end:HH:mm}" : $"{day} {start:HH:mm} → {end.ToString("dddd d HH:mm", Es)}";
    }
}
