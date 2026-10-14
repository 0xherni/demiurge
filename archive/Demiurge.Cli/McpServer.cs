using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Demiurge.Core.Ipc;

namespace Demiurge.Cli;

/// <summary>
/// Servidor MCP local (stdio, JSON-RPC 2.0) de SÓLO LECTURA sobre los resultados del escaneo.
/// Permite preguntarle a Claude Desktop "¿por qué me marcó este programa?" o "¿qué cambió desde el martes?".
/// No ejecuta acciones: éstas siguen pasando por la UI con confirmación. El LLM nunca decide el veredicto.
/// </summary>
internal static class McpServer
{
    private const string ProtocolVersion = "2025-06-18";

    private static readonly JsonArray Tools =
    [
        Tool("get_verdict", "Veredicto global del último escaneo de Demiurge (Limpio / Revisar / Probable infección), salud del sistema y resumen de hallazgos.", new JsonObject()),
        Tool("list_findings", "Hallazgos explicados: cada entidad con score, '¿Qué encontramos?', '¿Por qué?', '¿Qué tan grave?', '¿Qué hago?'.",
            new JsonObject { ["all"] = new JsonObject { ["type"] = "boolean", ["description"] = "Incluir también entidades de nivel Info" } }),
        Tool("get_entity_detail", "Detalle técnico de una entidad (binario, proceso, persistencia, extensión...): firma, hashes, reputación, árbol de procesos, conexiones, señales y técnicas ATT&CK.",
            new JsonObject { ["key"] = new JsonObject { ["type"] = "string", ["description"] = "scoringKey o clave de entidad (de list_findings o get_inventory)" } }, ["key"]),
        Tool("get_inventory", "Inventario de la PC con '¿Qué es esto?' y '¿Es normal?' por elemento.",
            new JsonObject
            {
                ["tab"] = new JsonObject { ["type"] = "string", ["enum"] = new JsonArray("startup", "processes", "connections", "extensions", "software", "accounts", "settings", "certificates", "drivers", "files") },
                ["search"] = new JsonObject { ["type"] = "string" },
            }, ["tab"]),
        Tool("get_diff", "Novedades desde el escaneo anterior: programas de arranque, software, extensiones, cuentas y certificados nuevos.", new JsonObject()),
        Tool("list_scans", "Historial de escaneos con fecha y veredicto.", new JsonObject()),
    ];

    private static JsonObject Tool(string name, string description, JsonObject props, string[]? required = null) => new()
    {
        ["name"] = name,
        ["description"] = description,
        ["inputSchema"] = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = props,
            ["required"] = new JsonArray((required ?? []).Select(r => (JsonNode)JsonValue.Create(r)!).ToArray()),
        },
        ["annotations"] = new JsonObject { ["readOnlyHint"] = true },
    };

    public static async Task<int> RunAsync()
    {
        Console.InputEncoding = Encoding.UTF8;
        var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true };
        var stdin = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
        IDemiurgeClient? client = null;

        string? line;
        while ((line = await stdin.ReadLineAsync()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            JsonNode? msg;
            try { msg = JsonNode.Parse(line); }
            catch (JsonException) { await Send(stdout, Error(null, -32700, "Parse error")); continue; }

            var id = msg?["id"]?.DeepClone();
            var method = msg?["method"]?.ToString();
            if (id is null) continue; // notificación (p.ej. notifications/initialized)

            try
            {
                JsonNode result = method switch
                {
                    "initialize" => new JsonObject
                    {
                        ["protocolVersion"] = msg?["params"]?["protocolVersion"]?.ToString() ?? ProtocolVersion,
                        ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() },
                        ["serverInfo"] = new JsonObject { ["name"] = "demiurge", ["version"] = Demiurge.Core.ScanOrchestrator.AppVersion },
                        ["instructions"] = "Resultados de Demiurge, un analizador de seguridad para PCs domésticas. Explicá en lenguaje simple; nunca afirmes que la PC está 100% limpia; el veredicto lo decide Demiurge, no vos.",
                    },
                    "ping" => new JsonObject(),
                    "tools/list" => new JsonObject { ["tools"] = Tools.DeepClone() },
                    "tools/call" => await CallTool(msg?["params"], () => client ??= Connect()),
                    _ => throw new McpException(-32601, $"Método no soportado: {method}"),
                };
                await Send(stdout, new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["result"] = result });
            }
            catch (McpException ex)
            {
                await Send(stdout, Error(id, ex.Code, ex.Message));
            }
            catch (Exception ex)
            {
                // Errores de herramienta se devuelven como resultado con isError (el modelo los ve).
                await Send(stdout, new JsonObject
                {
                    ["jsonrpc"] = "2.0", ["id"] = id,
                    ["result"] = new JsonObject { ["isError"] = true, ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = ex.Message }) },
                });
            }
        }
        if (client is not null) await client.DisposeAsync();
        return 0;
    }

    private static IDemiurgeClient Connect()
    {
        var c = ServiceClient.TryConnectAsync().GetAwaiter().GetResult();
        return c ?? throw new InvalidOperationException("El servicio Demiurge no está corriendo. Instalalo con 'demiurge service install'.");
    }

    private static async Task<JsonNode> CallTool(JsonNode? p, Func<IDemiurgeClient> client)
    {
        var name = p?["name"]?.ToString();
        var args = p?["arguments"] as JsonObject ?? new JsonObject();
        JsonNode? data = name switch
        {
            "get_verdict" => await client().CallAsync("scan.latest"),
            "list_findings" => await client().CallAsync("findings.list", new { all = args["all"]?.GetValueKind() == JsonValueKind.True }),
            "get_entity_detail" => await client().CallAsync("entity.detail", new { key = args["key"]?.ToString() }),
            "get_inventory" => await client().CallAsync("inventory", new { tab = args["tab"]?.ToString() ?? "startup", search = args["search"]?.ToString() }),
            "get_diff" => await client().CallAsync("diff"),
            "list_scans" => await client().CallAsync("scan.list"),
            _ => throw new McpException(-32602, $"Herramienta desconocida: {name}"),
        };
        var text = data?.ToJsonString(new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }) ?? "Sin datos (¿todavía no se corrió ningún escaneo?)";
        if (text.Length > 200_000) text = text[..200_000] + "…(recortado)";
        return new JsonObject { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = text }) };
    }

    private static JsonObject Error(JsonNode? id, int code, string message) =>
        new() { ["jsonrpc"] = "2.0", ["id"] = id, ["error"] = new JsonObject { ["code"] = code, ["message"] = message } };

    private static Task Send(StreamWriter w, JsonNode msg) => w.WriteLineAsync(msg.ToJsonString());

    private sealed class McpException(int code, string message) : Exception(message)
    {
        public int Code { get; } = code;
    }
}
