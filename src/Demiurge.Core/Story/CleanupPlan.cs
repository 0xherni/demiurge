using System.Text.RegularExpressions;
using Demiurge.Core.Model;
using Demiurge.Core.Storage;
using Demiurge.Core.Text;

namespace Demiurge.Core.Story;

public sealed class PlanStep
{
    public string Id { get; set; } = "";
    /// <summary>manual | action | questions | passwords | scan</summary>
    public string Kind { get; set; } = "manual";
    public string Title { get; set; } = "";
    public string Body { get; set; } = "";
    public string? Action { get; set; }
    public string? EntityKey { get; set; }
    public string? EntityName { get; set; }
    /// <summary>danger | review: en lo que es "para revisar" el paso es condicional ("si no lo reconocés").</summary>
    public string? Level { get; set; }
    /// <summary>Para pasos de acción: ya se hizo (hay una acción registrada y no revertida después del escaneo).</summary>
    public bool Done { get; set; }
    /// <summary>Lista de cosas concretas (cuentas a cambiar, preguntas pendientes).</summary>
    public List<string> Items { get; set; } = new();
    /// <summary>Para pasos de pregunta: se contesta desde el plan.</summary>
    public string? QuestionId { get; set; }
    public List<UserQuestionOption>? Options { get; set; }
}

public sealed class PlanPhase
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    /// <summary>Por qué este paso, en una frase.</summary>
    public string Why { get; set; } = "";
    public List<PlanStep> Steps { get; set; } = new();
}

public sealed class CleanupPlan
{
    /// <summary>Escaneo del que sale el plan (los pasos manuales tildados se recuerdan por escaneo).</summary>
    public long ScanId { get; set; }
    /// <summary>clean | cleanup</summary>
    public string Status { get; set; } = "clean";
    public string Intro { get; set; } = "";
    public List<PlanPhase> Phases { get; set; } = new();
}

/// <summary>
/// Plan de limpieza guiado: convierte las tarjetas del último escaneo en pasos ordenados (primero lo que corta el daño,
/// después lo que evita que vuelva, después lo que deshace sus cambios) para alguien que no sabe por dónde empezar.
/// No inventa nada: cada paso sale de una acción que la tarjeta ya ofrece o de lo que la tarjeta dice que hay que hacer.
/// </summary>
public static class CleanupPlanBuilder
{
    private static readonly string[] StopActions = ["kill_process"];
    private static readonly string[] StartupActions = ["disable_startup", "remove_wmi", "remove_ifeo"];
    private static readonly string[] UndoActions = ["repair_app", "restore_browser", "restore_hosts", "restore_proxy", "remove_extension", "remove_notifications", "remove_exclusion", "remove_certificate", "disable_account"];
    private static readonly string[] IsolateActions = ["quarantine"];

    /// <summary>Tipos de registro que deja cada acción (ActionService) para saber si un paso ya se hizo.</summary>
    private static readonly Dictionary<string, string[]> RecordTypes = new()
    {
        ["kill_process"] = ["kill"],
        ["disable_startup"] = ["registry_value", "file_move", "task_disable", "service_start", "registry_tree"],
        ["remove_ifeo"] = ["registry_value"],
        ["remove_wmi"] = ["wmi"],
        ["quarantine"] = ["quarantine"],
        ["remove_exclusion"] = ["defender_exclusion"],
        ["restore_hosts"] = ["file_copy"],
        ["restore_proxy"] = ["proxy"],
        ["restore_browser"] = ["registry_values", "file_copy"],
        ["remove_extension"] = ["file_move", "multi_file", "file_copy"],
        ["remove_notifications"] = ["file_copy"],
        ["repair_app"] = ["file_copy"],
        ["disable_account"] = ["account"],
        ["remove_certificate"] = ["certificate"],
    };

    /// <summary>Señales de que pudo haber un ladrón de contraseñas: entonces hay que cambiarlas.</summary>
    private static readonly HashSet<string> StealerHeuristics = ["H-34", "H-38", "H-39", "H-40"];
    private static readonly Regex StealerFamily = new(@"stealer|pws|lumma|redline|vidar|raccoon|stealc|azorult|agenttesla|agent tesla|formbook|grabber|infostealer|spy\b|\brat\b|remcos|asyncrat|njrat", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static CleanupPlan Build(ScanSnapshot s, IReadOnlyList<ActionRecord> actions, TextCatalog text)
    {
        var plan = new CleanupPlan { ScanId = s.Scan.Id };
        var flagged = s.Scores.Where(x => x.Level != EntityLevel.Info || x.PendingQuestion is not null).OrderByDescending(x => x.Score).ToList();
        if (flagged.Count == 0)
        {
            plan.Intro = "No hay nada que limpiar: el último escaneo no encontró nada que necesite tu atención.";
            return plan;
        }
        plan.Status = "cleanup";
        bool danger = flagged.Any(x => x.Level == EntityLevel.Peligroso);
        plan.Intro = danger
            ? "Seguí los pasos en orden. Cada acción se puede deshacer desde Actividad. Si en algún paso dudás, no lo hagas: preguntale a alguien de confianza mostrándole esta pantalla."
            : "No encontramos nada grave, pero hay cosas para revisar. Seguí los pasos en orden; cada acción se puede deshacer desde Actividad.";

        var findingsBy = s.Findings.GroupBy(f => f.ScoringKey).ToDictionary(g => g.Key, g => g.ToList());
        var since = s.Scan.Started;
        var liveActions = actions.Where(a => !a.Reverted && a.Date >= since).ToList();

        // 1) Preguntas: la respuesta cambia lo que hay que hacer.
        var questions = flagged.Where(x => x.PendingQuestion is not null).ToList();
        if (questions.Count > 0)
        {
            plan.Phases.Add(new PlanPhase
            {
                Id = "questions", Title = "Contestá las preguntas",
                Why = "Hay cosas que sólo vos sabés (por ejemplo, si instalaste un programa). Tu respuesta cambia el resto del plan.",
                Steps = questions.Select(q => new PlanStep
                {
                    Id = $"q:{q.ScoringKey}", Kind = "questions", Title = q.PendingQuestion!.Text, EntityKey = q.ScoringKey, EntityName = q.DisplayName,
                    Body = q.WhatWeFound, QuestionId = q.PendingQuestion.QuestionId, Options = q.PendingQuestion.Options,
                }).ToList(),
            });
        }

        // 2) Cortar internet si hay algo peligroso.
        if (danger)
        {
            plan.Phases.Add(new PlanPhase
            {
                Id = "offline", Title = "Desconectá la PC de internet",
                Why = "Así lo que haya en la PC no puede seguir mandando datos mientras limpiás. Los pasos de Demiurge funcionan sin internet.",
                Steps =
                [
                    new PlanStep
                    {
                        Id = "offline", Kind = "manual", Title = "Desconectá el cable de red o apagá el Wi-Fi",
                        Body = "En la barra de tareas, abajo a la derecha, tocá el ícono de red y apagá el Wi-Fi. Si usás cable, desenchufalo. Lo volvés a conectar al final.",
                    },
                ],
            });
        }

        var actionable = flagged.Where(x => x.PendingQuestion is null || x.Score > 0).ToList();
        AddActionPhase(plan, "stop", "Cerrá lo que está corriendo", "Un programa abierto puede volver a crear lo que borres. Primero se cierra.", StopActions, actionable, findingsBy, s, liveActions, text);
        AddActionPhase(plan, "startup", "Evitá que vuelva a arrancar solo", "Si no, aparece de nuevo la próxima vez que prendas la PC.", StartupActions, actionable, findingsBy, s, liveActions, text);
        AddActionPhase(plan, "undo", "Deshacé los cambios que hizo", "Volvemos a la normalidad lo que modificó: navegador, extensiones, antivirus, aplicaciones.", UndoActions, actionable, findingsBy, s, liveActions, text);
        // Cuarentena sólo para lo peligroso: en lo que es "para revisar", sacar el archivo puede romper un programa legítimo.
        AddActionPhase(plan, "isolate", "Aislá los archivos sospechosos", "La cuarentena los saca de su lugar sin borrarlos: si te equivocaste, se pueden restaurar.", IsolateActions,
            actionable.Where(x => x.Level == EntityLevel.Peligroso).ToList(), findingsBy, s, liveActions, text);

        // Tarjetas sin acción automática (inicio de sesión remoto, comandos pegados, eventos): lo que la tarjeta dice que hagas.
        var manual = actionable.Where(x => x.Level != EntityLevel.Info && !x.AvailableActions.Any(a => a != "allowlist")).ToList();
        if (manual.Count > 0)
        {
            plan.Phases.Add(new PlanPhase
            {
                Id = "manual", Title = "Revisá esto vos",
                Why = "Para esto no hay un botón: depende de algo que tenés que hacer o confirmar vos.",
                Steps = manual.Select(x => new PlanStep { Id = $"m:{x.ScoringKey}", Kind = "manual", Title = x.DisplayName, Body = x.WhatToDo, EntityKey = x.ScoringKey, EntityName = x.DisplayName }).ToList(),
            });
        }

        // Contraseñas, si hubo señales de robo de contraseñas o sesiones.
        if (StealerSuspected(s, flagged, findingsBy))
        {
            plan.Phases.Add(new PlanPhase
            {
                Id = "passwords", Title = "Cambiá tus contraseñas desde otro dispositivo",
                Why = "Encontramos señales de un programa que roba contraseñas y sesiones. Cambiarlas deja afuera a quien las tenga.",
                Steps =
                [
                    new PlanStep
                    {
                        Id = "passwords", Kind = "passwords", Title = "Cambiá las contraseñas desde el celular u otra PC",
                        Body = "No uses esta PC hasta terminar la limpieza. Empezá por el mail: con el mail se puede recuperar todo lo demás. En cada servicio, buscá \"cerrar todas las sesiones\" y activá la verificación en dos pasos.",
                        Items = AccountsAtRisk(s),
                    },
                ],
            });
        }

        plan.Phases.Add(new PlanPhase
        {
            Id = "verify", Title = "Verificá que quedó limpio",
            Why = "Un escaneo nuevo confirma que lo que limpiaste no volvió.",
            Steps =
            [
                new PlanStep
                {
                    Id = "rescan", Kind = "scan", Title = "Volvé a escanear",
                    Body = danger ? "Reiniciá la PC y escaneá de nuevo. Si da verde, ya podés volver a conectar internet." : "Escaneá de nuevo para confirmar que todo quedó bien.",
                },
            ],
        });
        return plan;
    }

    private static void AddActionPhase(CleanupPlan plan, string id, string title, string why, string[] kinds, List<EntityScore> flagged,
        Dictionary<string, List<Finding>> findingsBy, ScanSnapshot s, List<ActionRecord> actions, TextCatalog text)
    {
        var steps = new List<PlanStep>();
        foreach (var x in flagged)
        {
            bool review = x.Level != EntityLevel.Peligroso;
            foreach (var action in x.AvailableActions.Where(kinds.Contains).Distinct())
            {
                steps.Add(new PlanStep
                {
                    Id = $"{action}:{x.ScoringKey}", Kind = "action", Action = action, EntityKey = x.ScoringKey, EntityName = x.DisplayName,
                    Level = review ? "review" : "danger",
                    // Lo "para revisar" puede ser legítimo: el paso es condicional y se ofrece "Lo reconozco" al lado.
                    Title = review ? $"Si no reconocés {x.DisplayName}: {Lower(text[$"action.{action}"])}" : $"{text[$"action.{action}"]}: {x.DisplayName}",
                    Body = x.WhyItCaughtOurAttention.FirstOrDefault() ?? x.WhatWeFound,
                    Done = IsDone(action, RelatedKeys(x.ScoringKey, findingsBy, s), actions),
                });
            }
        }
        if (steps.Count > 0) plan.Phases.Add(new PlanPhase { Id = id, Title = title, Why = why, Steps = steps });
    }

    /// <summary>Claves sobre las que una acción pudo haber quedado registrada para esta tarjeta.</summary>
    private static HashSet<string> RelatedKeys(string scoringKey, Dictionary<string, List<Finding>> findingsBy, ScanSnapshot s)
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { scoringKey };
        foreach (var f in findingsBy.GetValueOrDefault(scoringKey) ?? []) keys.Add(f.EntityKey);
        foreach (var p in s.Persistence.Where(p => p.BinaryKey == scoringKey)) keys.Add(p.Key);
        return keys;
    }

    private static bool IsDone(string action, HashSet<string> keys, List<ActionRecord> actions)
    {
        if (!RecordTypes.TryGetValue(action, out var types)) return false;
        // Quitar el proxy queda registrado sobre toda la configuración de red, no sobre la tarjeta.
        return actions.Any(a => types.Contains(a.Type) && (keys.Contains(a.Target) || (action == "restore_proxy" && a.Target == "network_proxy")));
    }

    private static bool StealerSuspected(ScanSnapshot s, List<EntityScore> flagged, Dictionary<string, List<Finding>> findingsBy)
    {
        foreach (var x in flagged.Where(x => x.Level != EntityLevel.Info))
        {
            foreach (var f in findingsBy.GetValueOrDefault(x.ScoringKey) ?? [])
            {
                if (f.Weight <= 0) continue;
                if (StealerHeuristics.Contains(f.HeuristicId) && f.Weight >= 25) return true;
                var family = f.RawData["family"]?.ToString();
                if (family is not null && StealerFamily.IsMatch(family)) return true;
            }
        }
        return s.Defender.Detections.Any(d => d.Time >= DateTimeOffset.Now.AddDays(-30) && StealerFamily.IsMatch(d.ThreatName));
    }

    /// <summary>Cuentas que esta PC tenía a mano, en orden de importancia.</summary>
    internal static List<string> AccountsAtRisk(ScanSnapshot s)
    {
        var list = new List<string> { "Tu mail principal (Gmail, Outlook…): primero, porque con él se recupera todo lo demás", "Banco y billeteras virtuales (Mercado Pago, etc.)" };
        var browsers = s.Extensions.Select(e => e.Browser).Concat(s.BrowserSettings.Select(b => b.Browser)).Where(b => !string.IsNullOrWhiteSpace(b)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (browsers.Count > 0)
            list.Add($"Todas las contraseñas guardadas en {JoinEs(browsers)} (el navegador las guarda y estos programas las leen)");
        var names = s.Software.Select(x => x.Name).ToList();
        bool Has(string n) => names.Any(x => x.Contains(n, StringComparison.OrdinalIgnoreCase));
        if (s.AppIntegrity.Count > 0 || Has("Discord")) list.Add("Discord");
        foreach (var (match, label) in new[] { ("Steam", "Steam"), ("Epic Games", "Epic Games"), ("Battle.net", "Battle.net"), ("Riot", "Riot Games"), ("Telegram", "Telegram"), ("WhatsApp", "WhatsApp (cerrá las sesiones de WhatsApp Web)"), ("Exodus", "Exodus (billetera cripto: mové los fondos a una billetera nueva)"), ("Atomic Wallet", "Atomic Wallet (billetera cripto: mové los fondos a una billetera nueva)") })
            if (Has(match)) list.Add(label);
        if (s.Extensions.Any(e => e.Name.Contains("MetaMask", StringComparison.OrdinalIgnoreCase)))
            list.Add("MetaMask (billetera cripto: mové los fondos a una billetera nueva, no alcanza con cambiar la contraseña)");
        list.Add("Redes sociales (Instagram, Facebook, X, TikTok)");
        return list;
    }

    private static string Lower(string s) => s.Length == 0 ? s : char.ToLowerInvariant(s[0]) + s[1..];

    private static string JoinEs(List<string> parts) =>
        parts.Count == 1 ? parts[0] : string.Join(", ", parts.Take(parts.Count - 1)) + " y " + parts[^1];
}
