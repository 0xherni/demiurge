using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Rules;
using Demiurge.Core.Text;

namespace Demiurge.Core.Scoring;

/// <summary>
/// 06_Scoring: agrega findings por entidad y calcula el veredicto. Determinístico y explicable:
/// cada veredicto se puede listar como entidad → findings → datos crudos.
/// </summary>
public sealed class ScoringEngine
{
    private readonly TextCatalog _text;
    private readonly KnowledgeBase _kb;

    public ScoringEngine(TextCatalog text, KnowledgeBase kb)
    {
        _text = text;
        _kb = kb;
    }

    public sealed class Inputs
    {
        public required ScanSnapshot Snapshot { get; init; }
        public required RuleSet Rules { get; init; }
        public required RuleContext Context { get; init; }
        public HashSet<string> UserAllowlist { get; init; } = new();
        public Dictionary<string, FindingState> FindingStates { get; init; } = new();
        /// <summary>heuristic|entity de findings del escaneo anterior (para nuevo/visto).</summary>
        public HashSet<string> PreviousFindingKeys { get; init; } = new();
    }

    public void Score(Inputs input)
    {
        var s = input.Snapshot;
        var p = input.Rules.Scoring;
        var never = p.NeverIgnore.ToHashSet();
        var hardIgnores = p.HardAllowlistIgnores.ToHashSet();

        // 1) Ajustes de peso: allowlist dura, allowlist del usuario, estado del finding.
        foreach (var f in s.Findings)
        {
            var bin = s.GetBinary(f.ScoringKey) ?? s.GetBinary(FindBinaryKey(s, f));
            if (hardIgnores.Contains(f.HeuristicId) && !never.Contains(f.HeuristicId) && input.Context.IsHardAllowlisted(bin))
            {
                f.Weight = 0;
                f.Suppression = bin?.Signature?.IsMicrosoft == true ? "Firmado por Microsoft"
                    : bin?.IsKnownGood == true ? "Software conocido (CIRCL hashlookup / NSRL)"
                    : "Programa conocido (base de conocimiento)";
            }

            var stateKey = $"{f.HeuristicId}|{f.EntityKey}";
            bool userAllowed = input.UserAllowlist.Contains(f.ScoringKey) || input.UserAllowlist.Contains(f.EntityKey);
            if (input.FindingStates.TryGetValue(stateKey, out var st))
                f.State = st;
            else
                f.State = input.PreviousFindingKeys.Contains(stateKey) ? FindingState.Visto : FindingState.Nuevo;

            if ((userAllowed || f.State is FindingState.Ignorado or FindingState.Resuelto) && f.Severity != Severity.Critica && f.Weight > 0)
            {
                f.Weight = 0;
                f.Suppression = userAllowed ? "Marcado por vos como 'Lo reconozco'" : f.State == FindingState.Resuelto ? "Marcado como resuelto" : "Ignorado por vos";
            }
        }

        // 2) Score por entidad de scoring.
        var scores = new List<EntityScore>();
        foreach (var group in s.Findings.GroupBy(f => f.ScoringKey))
        {
            // La misma heurística sobre la misma entidad cuenta una sola vez (máximo peso).
            var distinct = group.GroupBy(f => f.HeuristicId).Select(g => g.OrderByDescending(f => f.Weight).First()).ToList();
            int raw = distinct.Sum(f => f.Weight);
            int categories = distinct.Where(f => f.Weight > 0).Select(f => f.Category).Distinct().Count();
            bool bonus = categories >= p.AccumulationMinCategories;
            int score = bonus ? (int)Math.Round(raw * (1 + p.AccumulationBonus)) : raw;
            bool critical = distinct.Any(f => f.Severity == Severity.Critica && f.Weight > 0);

            var es = new EntityScore
            {
                ScoringKey = group.Key,
                Score = score,
                RawSum = raw,
                AccumulationBonus = bonus,
                CriticalOverride = critical,
                Level = critical || score >= p.DangerMin ? EntityLevel.Peligroso : score >= p.ReviewMin ? EntityLevel.Revisar : EntityLevel.Info,
                MaxSeverity = distinct.Where(f => f.Weight > 0 || f.Severity == Severity.Pregunta).Select(f => f.Severity).DefaultIfEmpty(Severity.Info).Max(),
                FindingIds = group.Select(f => f.Id).ToList(),
                AttackIds = group.SelectMany(f => f.AttackIds).Distinct().OrderBy(x => x).ToList(),
            };
            Describe(es, group.ToList(), s);
            scores.Add(es);
        }

        s.Scores = scores.OrderByDescending(x => x.Level).ThenByDescending(x => x.Score).ToList();
        s.Scan.ScoreMax = s.Scores.Select(x => x.CriticalOverride ? Math.Max(x.Score, p.DangerMin) : x.Score).DefaultIfEmpty(0).Max();

        // 3) Veredicto global.
        int review = s.Scores.Count(x => x.Level == EntityLevel.Revisar);
        int danger = s.Scores.Count(x => x.Level == EntityLevel.Peligroso);
        s.Verdict = danger > 0 ? GlobalVerdict.ProbableInfeccion : review > 0 ? GlobalVerdict.Revisar : GlobalVerdict.Limpio;
        s.VerdictText = s.Verdict switch
        {
            GlobalVerdict.ProbableInfeccion => _text["verdict.ProbableInfeccion"],
            GlobalVerdict.Revisar => review == 1 ? _text["verdict.Revisar.one"] : _text.Get("verdict.Revisar.many", ("n", review)),
            _ => _text["verdict.Limpio"],
        };
        s.Scan.Verdict = s.Verdict;

        // 4) Salud del sistema (separada: no mezclar postura con infección).
        s.Health = BuildHealth(s);
        s.Scan.HealthSummary = s.Health.Summary;
    }

    private static string? FindBinaryKey(ScanSnapshot s, Finding f) => f.EntityKind switch
    {
        EntityKind.Process => s.Processes.FirstOrDefault(p => p.Key == f.EntityKey)?.BinaryKey,
        EntityKind.Persistence => s.Persistence.FirstOrDefault(p => p.Key == f.EntityKey)?.BinaryKey,
        EntityKind.Binary => f.EntityKey,
        _ => null,
    };

    // ---------------- Tarjeta de 4 preguntas ----------------

    private void Describe(EntityScore es, List<Finding> findings, ScanSnapshot s)
    {
        var active = findings.Where(f => f.Weight > 0 || f.Question is not null).OrderByDescending(f => f.Weight).ToList();
        var main = active.FirstOrDefault() ?? findings.OrderByDescending(f => f.BaseWeight).First();
        var bin = s.GetBinary(es.ScoringKey);

        es.Kind = bin is not null ? EntityKind.Binary : main.EntityKind;
        es.DisplayName = bin?.DisplayName ?? main.EntityName;
        es.Path = bin?.Path;

        // ¿Qué encontramos? (una línea sin jerga)
        var ids = active.Select(f => f.HeuristicId).ToHashSet();
        var parts = new List<string>();
        if (ids.Contains("H-01")) parts.Add(_text["found.malicious"]);
        if (ids.Contains("H-05")) parts.Add(_text["found.masquerade"]);
        if (ids.Overlaps(["H-08", "H-09", "H-10"])) parts.Add(_text["found.persistence"]);
        if (ids.Overlaps(["H-02"])) parts.Add(_text["found.badnetwork"]);
        else if (ids.Overlaps(["H-14", "H-25"])) parts.Add(_text["found.network"]);
        if (ids.Contains("H-13")) parts.Add(_text["found.miner"]);
        if (ids.Overlaps(["H-07", "H-23"])) parts.Add(_text["found.lolbin"]);
        if (ids.Contains("H-06")) parts.Add(_text["found.parentchild"]);
        if (ids.Contains("H-27")) parts.Add(_text["found.memory"]);

        var subject = _text[$"subject.{es.Kind}"];
        if (es.Kind == EntityKind.Binary && ids.Contains("H-03") && !ids.Contains("H-01")) subject += " " + _text["found.unknown"];
        es.WhatWeFound = parts.Count == 0
            ? main.Explanation
            : $"{subject} (\"{es.DisplayName}\") {JoinEs(parts)}.";

        // ¿Por qué nos llamó la atención?
        es.WhyItCaughtOurAttention = active.Select(f => f.Explanation).Distinct().ToList();
        if (es.WhyItCaughtOurAttention.Count == 0) es.WhyItCaughtOurAttention = findings.Select(f => f.Explanation).Distinct().ToList();

        // ¿Qué tan grave es?
        var level = _text[$"level.{es.Level}"];
        var category = active.FirstOrDefault()?.Category ?? main.Category;
        var context = _text.Has($"serious.{category}") ? _text[$"serious.{category}"] : _text["serious.default"];
        es.HowSerious = es.MaxSeverity == Severity.Pregunta && es.Score == 0
            ? $"{_text["severity.Pregunta"]}. {context}"
            : $"{_text[$"severity.{es.MaxSeverity}"]} ({level}). {context}";

        // ¿Qué hago?
        es.PendingQuestion = findings.Select(f => f.Question).FirstOrDefault(q => q is not null);
        var action = active.Select(f => f.RecommendedAction).FirstOrDefault(a => !string.IsNullOrWhiteSpace(a));
        es.WhatToDo = es.PendingQuestion is not null && es.Score == 0 ? _text["todo.question"]
            : action ?? (es.Level == EntityLevel.Info ? _text["todo.nothing"] : _text["todo.recognize"]);
        bool strong = ids.Overlaps(["H-01", "H-02", "H-27", "H-32", "H-33"]) ||
                      active.Any(f => f.HeuristicId == "H-26" && f.Weight >= 60);
        if (es.Level == EntityLevel.Peligroso && strong)
            es.WhatToDo = _text["verdict.immediate"] + " " + es.WhatToDo;

        es.AvailableActions = ActionsFor(findings, s).Distinct().ToList();
    }

    private static IEnumerable<string> ActionsFor(List<Finding> findings, ScanSnapshot s)
    {
        foreach (var f in findings)
        {
            switch (f.EntityKind)
            {
                case EntityKind.Persistence:
                    var item = s.Persistence.FirstOrDefault(p => p.Key == f.EntityKey);
                    if (item?.Type == PersistenceType.Wmi) yield return "remove_wmi";
                    else if (item?.Type == PersistenceType.Ifeo) yield return "remove_ifeo";
                    else yield return "disable_startup";
                    break;
                case EntityKind.Process when s.Processes.Any(p => p.Key == f.EntityKey && p.EndTime is null):
                    yield return "kill_process";
                    break;
                case EntityKind.Extension:
                    yield return "remove_extension";
                    break;
                case EntityKind.BrowserSetting when f.HeuristicId == "H-20":
                    yield return "remove_notifications";
                    break;
                case EntityKind.BrowserSetting:
                    yield return "restore_browser";
                    break;
                case EntityKind.Account:
                    yield return "disable_account";
                    break;
                case EntityKind.Certificate:
                    yield return "remove_certificate";
                    break;
                case EntityKind.SystemSetting when f.HeuristicId == "H-11":
                    yield return "remove_exclusion";
                    break;
                case EntityKind.SystemSetting when f.HeuristicId == "H-15":
                    yield return f.ScoringKey == "hosts" ? "restore_hosts" : "restore_proxy";
                    break;
            }
            // Persistencias del mismo binario: ofrecer deshabilitarlas desde la tarjeta del binario.
            if (f.EntityKind == EntityKind.Binary && s.Persistence.Any(p => p.BinaryKey == f.ScoringKey))
                yield return "disable_startup";
            if (f.EntityKind == EntityKind.Binary && s.Processes.Any(p => p.BinaryKey == f.ScoringKey && p.EndTime is null))
                yield return "kill_process";
        }
        if (findings.Any(f => s.GetBinary(f.ScoringKey) is { Exists: true }) ) yield return "quarantine";
        yield return "allowlist";
    }

    private static string JoinEs(List<string> parts) =>
        parts.Count == 1 ? parts[0] : string.Join(", ", parts.Take(parts.Count - 1)) + " y " + parts[^1];

    // ---------------- Salud ----------------

    private HealthReport BuildHealth(ScanSnapshot s)
    {
        var items = s.Settings.Where(x => x.Category == "health" && x.Name is not "other_av").ToList();
        var bad = items.Where(x => x.Ok == false).ToList();
        var report = new HealthReport
        {
            Items = items,
            Level = bad.Count == 0 ? "buena" : "mejorable",
        };
        report.Summary = bad.Count == 0
            ? $"{_text["health.buena"]}. {_text["health.ok"]}"
            : $"{_text["health.mejorable"]}. " + string.Join(" ", bad.Select(b => _text.Get($"health.{b.Name}", ("value", b.Value))));
        return report;
    }
}
