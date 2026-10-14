using System.Text.Json;
using System.Text.Json.Nodes;
using Demiurge.Core.Ipc;

namespace Demiurge.Cli;

/// <summary>Presentación en consola de las 3 capas (veredicto, hallazgos, inventario).</summary>
internal static class Render
{
    public static void Help()
    {
        Console.WriteLine("""
            Demiurge — ¿está limpia mi PC?

            Uso: demiurge <comando> [opciones]   (--json: salida cruda · correr como administrador)

              scan [--deep]                 Escanear (completo; --deep suma memoria/YARA/Sigma si están configurados)
              status                        Veredicto del último escaneo (capa 1)
              findings [--all]              Hallazgos explicados (capa 2)
              detail <clave>                Detalle técnico de una entidad
              inventory <pestaña> [--search texto]
                                            startup | processes | connections | extensions | software |
                                            accounts | settings | certificates | drivers | files  (capa 3)
              diff                          Novedades desde el escaneo anterior
              answer <clave> <pregunta> <respuesta>
                                            Responder una pregunta (ej. ¿Instalaste vos AnyDesk?)
              ack <H-xx> <clave> [Visto|Ignorado|Resuelto]
              action <acción> <clave> [--yes]
                                            disable_startup | kill_process | quarantine | remove_exclusion |
                                            restore_hosts | restore_proxy | restore_browser | remove_extension |
                                            remove_notifications | disable_account | remove_certificate |
                                            remove_wmi | remove_ifeo | allowlist
              actions / revert <id>         Historial de acciones / deshacer una acción
              allowlist [remove <clave>]    Ítems marcados como "lo reconozco"
              feeds                         Actualizar feeds de inteligencia
              config [clave=valor ...]      Ver/cambiar configuración (virusTotalApiKey, abuseChAuthKey, ...)
              tools pin <yarax|hollowshunter|hayabusa>
                                            Fijar el hash de una herramienta externa copiada a %ProgramData%\Demiurge\tools
              scans                         Historial de escaneos
            """);
    }

    public static void Warn(string msg) => WithColor(ConsoleColor.Yellow, () => Console.Error.WriteLine(msg)); // stderr: no ensucia --json
    public static void Error(string msg) => WithColor(ConsoleColor.Red, () => Console.Error.WriteLine("Error: " + msg));

    public static bool Confirm(string question)
    {
        Console.Write(question + " [s/N] ");
        var a = Console.ReadLine()?.Trim().ToLowerInvariant();
        return a is "s" or "si" or "sí" or "y" or "yes";
    }

    public static void Json(JsonNode? n) => Console.WriteLine(n?.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }) ?? "null");

    public static void Progress(JsonNode? p)
    {
        var pct = p?["percent"]?.GetValue<int>() ?? 0;
        var detail = p?["detail"]?.ToString() ?? p?["stage"]?.ToString() ?? "";
        if (detail.Length > 60) detail = detail[..57] + "…";
        Console.Write($"\r[{new string('█', pct / 5)}{new string('░', 20 - pct / 5)}] {pct,3}%  {detail,-60}");
    }

    private static string S(JsonNode? n, string key) => n?[key]?.ToString() ?? "";

    private static ConsoleColor LevelColor(string level) => level switch
    {
        "Peligroso" or "danger" => ConsoleColor.Red,
        "Revisar" or "review" => ConsoleColor.Yellow,
        "question" => ConsoleColor.Cyan,
        "info" => ConsoleColor.Gray,
        _ => ConsoleColor.Green,
    };

    public static void Summary(JsonNode? s)
    {
        if (s is null) return;
        var verdict = S(s, "verdict");
        var color = verdict switch { "Limpio" => ConsoleColor.Green, "Revisar" => ConsoleColor.Yellow, _ => ConsoleColor.Red };
        Console.WriteLine();
        WithColor(color, () => Console.WriteLine($"  {S(s, "verdictIcon")}  {S(s, "verdictText")}"));
        Console.WriteLine($"     Escaneo #{S(s, "scanId")} · {DateTimeOffset.Parse(S(s, "started")).ToLocalTime():dd/MM/yyyy HH:mm} · feeds {S(s, "feeds")}");
        if (s["immediate"] is { } imm) WithColor(ConsoleColor.Red, () => Console.WriteLine("     " + imm));
        if (s["elevatedWarning"] is { } ew) Warn("     " + ew);
        var health = s["health"];
        WithColor(S(health, "level") == "buena" ? ConsoleColor.Green : ConsoleColor.Yellow, () => Console.WriteLine($"\n  🛡  {S(health, "summary")}"));
        var c = s["counts"];
        Console.WriteLine($"\n     {S(c, "danger")} peligroso(s) · {S(c, "review")} para revisar · {S(c, "questions")} pregunta(s) · {S(c, "processes")} procesos · {S(c, "startup")} programas de arranque · {S(c, "extensions")} extensiones");

        if (s["findings"] is JsonArray arr && arr.Count > 0)
        {
            Console.WriteLine("\n  Hallazgos:");
            foreach (var f in arr) Card(f);
        }
        var failed = (s["collectors"] as JsonArray)?.Where(x => x?["success"]?.GetValue<bool>() == false).ToList();
        if (failed is { Count: > 0 })
            Warn($"\n  Algunas áreas no se pudieron revisar: {string.Join(", ", failed.Select(f => $"{S(f, "name")} ({S(f, "error")})"))}");
        WithColor(ConsoleColor.DarkGray, () => Console.WriteLine($"\n  {S(s, "disclaimer")}"));
    }

    public static void Findings(JsonNode n)
    {
        if (n is not JsonArray arr || arr.Count == 0) { WithColor(ConsoleColor.Green, () => Console.WriteLine("No hay hallazgos para revisar.")); return; }
        foreach (var f in arr) Card(f);
    }

    /// <summary>Tarjeta con las 4 preguntas de 08_UX_Explicaciones.</summary>
    public static void Card(JsonNode? f)
    {
        if (f is null) return;
        if (f["scoringKey"] is null) { Summary(f); return; }
        var level = S(f, "level");
        Console.WriteLine();
        WithColor(LevelColor(level), () => Console.WriteLine($"  ■ {S(f, "displayName")}  [{level} · score {S(f, "score")}]"));
        Console.WriteLine($"    ¿Qué encontramos?  {S(f, "whatWeFound")}");
        Console.WriteLine("    ¿Por qué nos llamó la atención?");
        foreach (var w in f["whyItCaughtOurAttention"]?.AsArray() ?? []) Console.WriteLine($"      • {w}");
        Console.WriteLine($"    ¿Qué tan grave es? {S(f, "howSerious")}");
        Console.WriteLine($"    ¿Qué hago?         {S(f, "whatToDo")}");
        if (f["pendingQuestion"] is { } q)
        {
            WithColor(ConsoleColor.Cyan, () =>
            {
                Console.WriteLine($"    ❓ {S(q, "text")}");
                foreach (var o in q["options"]?.AsArray() ?? [])
                    Console.WriteLine($"       demiurge answer \"{S(f, "scoringKey")}\" {S(q, "questionId")} {S(o, "value")}   → {S(o, "label")}");
            });
        }
        if (f["availableActions"] is JsonArray acts && acts.Count > 0)
            WithColor(ConsoleColor.DarkGray, () => Console.WriteLine($"    Acciones: {string.Join(" · ", acts.Select(a => a?.ToString()))}"));
        WithColor(ConsoleColor.DarkGray, () => Console.WriteLine($"    Detalle técnico: demiurge detail \"{S(f, "scoringKey")}\""));
    }

    public static void Detail(JsonNode d)
    {
        if (d["score"] is { } sc && sc.GetValueKind() != JsonValueKind.Null) Card(sc);
        var b = d["binary"];
        if (b is not null && b.GetValueKind() != JsonValueKind.Null)
        {
            Console.WriteLine("\n  Binario");
            Console.WriteLine($"    Ruta:     {S(b, "path")}");
            Console.WriteLine($"    SHA256:   {S(b, "sha256")}");
            Console.WriteLine($"    Tamaño:   {S(b, "size")} bytes · modificado {S(b, "modified")}");
            var sig = b["signature"];
            Console.WriteLine($"    Firma:    {(sig?["isValid"]?.GetValue<bool>() == true ? "válida" : sig?["isSigned"]?.GetValue<bool>() == true ? "INVÁLIDA" : "sin firma")} {S(sig, "signer")}{(sig?["isCatalogSigned"]?.GetValue<bool>() == true ? " (catálogo)" : "")}");
            foreach (var r in b["reputation"]?.AsArray() ?? []) Console.WriteLine($"    Reputación: {S(r, "source")}: {S(r, "verdict")} {S(r, "family")}");
        }
        if (d["knowledge"] is JsonObject kb) Console.WriteLine($"\n  ¿Qué es esto? {S(kb, "what")}\n  ¿Es normal?   {S(kb, "normal")}");
        Section("Árbol de procesos", d["processTree"], n => string.Join(" → ", n!.AsArray().Select(x => x?.ToString())));
        Section("Arranque", d["persistence"], p => $"{S(p, "type")} · {S(p, "location")} · {S(p, "command")}");
        Section("Conexiones", d["connections"], c => $"{S(c, "protocol")} {S(c, "remoteAddress")}:{S(c, "remotePort")} {S(c, "state")} {S(c, "tiMatch")}");
        Section("DNS", d["dns"], q => $"{S(q, "domain")} {S(q, "tiMatch")}");
        Section("Señales (heurística → datos crudos)", d["findings"], f => $"{S(f, "heuristicId")} {S(f, "heuristicName")} · peso {S(f, "weight")}{(f?["suppression"] is { } sup ? $" (ignorado: {sup})" : "")}\n        {f?["rawData"]?.ToJsonString()}");
        if (d["attack"] is JsonArray att && att.Count > 0) Console.WriteLine($"\n  MITRE ATT&CK: {string.Join(", ", att.Select(a => a?.ToString()))}");
    }

    private static void Section(string title, JsonNode? arr, Func<JsonNode?, string> line)
    {
        if (arr is not JsonArray a || a.Count == 0) return;
        Console.WriteLine($"\n  {title}");
        foreach (var x in a.Take(30)) Console.WriteLine($"    • {line(x)}");
    }

    public static void Inventory(JsonNode n)
    {
        foreach (var r in n.AsArray())
        {
            var status = S(r, "status");
            WithColor(LevelColor(status), () => Console.Write($"  {(status switch { "danger" => "🔴", "review" => "🟡", "question" => "❓", "info" => "·", _ => "🟢" })} "));
            Console.WriteLine($"{S(r, "name")}  {S(r, "detail")}");
            WithColor(ConsoleColor.DarkGray, () =>
            {
                if (r?["path"] is { } p) Console.WriteLine($"     {p}{(r["signer"] is { } sg ? $"  ({sg})" : "")}");
                Console.WriteLine($"     ¿Qué es esto? {S(r, "whatIsIt")}");
                Console.WriteLine($"     ¿Es normal?   {S(r, "isItNormal")}");
            });
        }
        Console.WriteLine($"\n  {n.AsArray().Count} elemento(s).");
    }

    public static void Diff(JsonNode d)
    {
        Console.WriteLine($"\n  {S(d, "title")}");
        foreach (var s in d["summary"]?.AsArray() ?? []) Console.WriteLine($"   • {s}");
        foreach (var i in d["items"]?.AsArray() ?? [])
        {
            var added = S(i, "change") == "added";
            WithColor(added ? (i?["score"]?.GetValue<int>() > 0 ? ConsoleColor.Yellow : ConsoleColor.Green) : ConsoleColor.DarkGray,
                () => Console.WriteLine($"     {(added ? "+" : "-")} [{S(i, "kind")}] {S(i, "name")}  {S(i, "detail")}"));
        }
    }

    public static void ActionResult(JsonNode r)
    {
        var ok = r["success"]?.GetValue<bool>() == true;
        WithColor(ok ? ConsoleColor.Green : ConsoleColor.Red, () => Console.WriteLine((ok ? "✔ " : "✘ ") + S(r, "message")));
        if (ok && r["reversible"]?.GetValue<bool>() == true) Console.WriteLine($"  Para deshacer: demiurge revert {S(r, "actionId")}");
    }

    public static void Actions(JsonNode n)
    {
        foreach (var a in n.AsArray())
            Console.WriteLine($"  {S(a, "id")}  {DateTimeOffset.Parse(S(a, "date")).ToLocalTime():dd/MM HH:mm}  {S(a, "type"),-18} {(a?["reverted"]?.GetValue<bool>() == true ? "(revertida) " : "")}{S(a, "description")}");
    }

    public static void Scans(JsonNode n)
    {
        foreach (var s in n.AsArray())
            Console.WriteLine($"  #{S(s, "id"),-4} {DateTimeOffset.Parse(S(s, "started")).ToLocalTime():dd/MM/yyyy HH:mm}  {S(s, "type"),-9} {S(s, "verdict"),-18} score máx {S(s, "scoreMax")}");
    }

    public static void LiveList(JsonNode n)
    {
        foreach (var e in n.AsArray().Take(20)) Live(e);
    }

    public static void Live(JsonNode? e)
    {
        var score = e?["score"]?.GetValue<int>() ?? 0;
        WithColor(score >= 60 ? ConsoleColor.Red : score >= 20 ? ConsoleColor.Yellow : ConsoleColor.Gray, () =>
            Console.WriteLine($"  [{DateTimeOffset.Parse(S(e, "timestamp")).ToLocalTime():HH:mm:ss}] {S(e, "title")} (score {score})"));
        WithColor(ConsoleColor.DarkGray, () => Console.WriteLine($"     {S(e, "detail")}"));
    }

    private static void WithColor(ConsoleColor c, Action a)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = c;
        try { a(); } finally { Console.ForegroundColor = prev; }
    }
}
