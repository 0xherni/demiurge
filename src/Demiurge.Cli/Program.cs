using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Demiurge.Cli;
using Demiurge.Core.Ipc;
using Demiurge.Core.Model;

Console.OutputEncoding = Encoding.UTF8;

var argList = args.ToList();
argList.Remove("--local"); // compatibilidad: ahora siempre es local
bool json = argList.Remove("--json");
bool yes = argList.Remove("--yes") | argList.Remove("-y");
bool verbose = argList.Remove("--verbose") | argList.Remove("-v");
var cmd = argList.ElementAtOrDefault(0)?.ToLowerInvariant() ?? "help";

if (cmd is "help" or "-h" or "--help") { Render.Help(); return 0; }

using var loggerFactory = LoggerFactory.Create(b =>
{
    b.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss "; });
    b.SetMinimumLevel(verbose ? LogLevel.Debug : LogLevel.Warning);
});
var logger = loggerFactory.CreateLogger("demiurge");

if (!Demiurge.Core.Native.CallerInfo.Self().Elevated)
    Render.Warn("Corriendo sin permisos de administrador: parte de la PC no se puede revisar. Abrí la consola como administrador.");
await using var client = new LocalClient(logger);

try
{
    switch (cmd)
    {
        case "scan":
        {
            var type = argList.Contains("--deep") ? ScanType.Profundo : ScanType.Completo;
            client.EventReceived += (e, d) => { if (e == "progress" && !json) Render.Progress(d); };
            var snap = await client.Engine.ScanAsync(type, CancellationToken.None);
            var summary = JsonSerializer.SerializeToNode(client.Engine.Summary(snap), Protocol.Json);
            Console.WriteLine();
            if (json) Render.Json(summary); else Render.Summary(summary);
            break;
        }
        case "status":
            Output(await client.CallAsync("scan.latest"), Render.Summary, "Todavía no hay escaneos. Corré 'demiurge scan'.");
            break;
        case "findings":
            Output(await client.CallAsync("findings.list", new { all = argList.Contains("--all") }), Render.Findings);
            break;
        case "detail":
            Output(await client.CallAsync("entity.detail", new { key = Arg(1, "clave de entidad") }), Render.Detail);
            break;
        case "inventory":
            Output(await client.CallAsync("inventory", new { tab = argList.ElementAtOrDefault(1) ?? "startup", search = Opt("--search") }), Render.Inventory);
            break;
        case "diff":
            Output(await client.CallAsync("diff"), Render.Diff);
            break;
        case "answer":
            Output(await client.CallAsync("answer", new { entityKey = Arg(1, "clave"), questionId = Arg(2, "pregunta"), answer = Arg(3, "respuesta") }), n => Render.Card(n));
            break;
        case "ack":
            Output(await client.CallAsync("finding.state", new { heuristicId = Arg(1, "heurística"), entityKey = Arg(2, "clave"), state = argList.ElementAtOrDefault(3) ?? "Ignorado" }), n => Render.Card(n));
            break;
        case "action":
        {
            var action = Arg(1, "acción");
            var key = Arg(2, "clave");
            if (!yes && !Render.Confirm($"¿Confirmás '{action}' sobre {key}? Es reversible (salvo finalizar procesos)."))
            {
                Render.Warn("Cancelado.");
                break;
            }
            Output(await client.CallAsync("action.execute", new { action, entityKey = key, confirmed = true }), Render.ActionResult);
            break;
        }
        case "revert":
            Output(await client.CallAsync("action.revert", new { id = Arg(1, "id de acción") }), Render.ActionResult);
            break;
        case "actions":
            Output(await client.CallAsync("action.list"), Render.Actions);
            break;
        case "allowlist":
            if (argList.ElementAtOrDefault(1) == "remove")
                Output(await client.CallAsync("allowlist.remove", new { entityKey = Arg(2, "clave") }), Render.Json);
            else
                Output(await client.CallAsync("allowlist.list"), Render.Json);
            break;
        case "feeds":
            Output(await client.CallAsync("feeds.update", timeout: TimeSpan.FromMinutes(10)), Render.Json);
            break;
        case "config":
        {
            if (argList.Count > 1)
            {
                var set = new JsonObject();
                foreach (var kv in argList.Skip(1).Select(a => a.Split('=', 2)).Where(p => p.Length == 2))
                    set[kv[0]] = bool.TryParse(kv[1], out var b) ? JsonValue.Create(b) : int.TryParse(kv[1], out var i) ? JsonValue.Create(i) : JsonValue.Create(kv[1]);
                Output(await client.CallAsync("config.set", set), Render.Json);
            }
            else Output(await client.CallAsync("config.get"), Render.Json);
            break;
        }
        case "tools":
            Output(await client.CallAsync("tools.pin", new { tool = Arg(2, "herramienta") }), Render.Json);
            break;
        case "scans":
            Output(await client.CallAsync("scan.list"), Render.Scans);
            break;
        case "ping":
            Output(await client.CallAsync("ping"), Render.Json);
            break;
        default:
            Render.Help();
            return 1;
    }
    return 0;
}
catch (Exception ex)
{
    Render.Error(ex.Message);
    if (verbose) Console.Error.WriteLine(ex);
    return 2;
}

string Arg(int i, string what) => argList.ElementAtOrDefault(i) ?? throw new ArgumentException($"Falta el argumento: {what}");
string? Opt(string name) { var i = argList.IndexOf(name); return i >= 0 ? argList.ElementAtOrDefault(i + 1) : null; }
void Output(JsonNode? node, Action<JsonNode> render, string? empty = null)
{
    if (node is null) { Render.Warn(empty ?? "Sin datos."); return; }
    if (json) Render.Json(node); else render(node);
}

