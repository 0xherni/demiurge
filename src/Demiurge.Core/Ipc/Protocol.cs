using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Demiurge.Core.Ipc;

/// <summary>
/// Contrato entre la interfaz (WebView2) y el motor, que corre dentro del mismo proceso: requests JSON con id,
/// respuestas con el mismo id y eventos push (progreso del escaneo) sin id. No hay servicio ni pipe: nada escucha
/// cuando la app está cerrada.
/// </summary>
public static class Protocol
{
    public const int Version = 1;

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Operaciones que se aceptan (todo lo demás se rechaza).</summary>
    public static readonly HashSet<string> Operations =
    [
        "ping", "scan.start", "scan.cancel", "scan.status", "scan.latest", "scan.list", "scan.get",
        "findings.list", "entity.detail", "inventory", "diff", "plan", "timeline", "answer", "finding.state",
        "action.execute", "action.revert", "action.list", "allowlist.list", "allowlist.remove",
        "feeds.update", "config.get", "config.set", "tools.pin",
    ];

    /// <summary>
    /// Defensa en profundidad: la app corre elevada, pero si algún día el motor se expone a un proceso sin elevar,
    /// éste sólo podría ver el estado y el veredicto.
    /// </summary>
    public static readonly HashSet<string> PublicOperations =
        ["ping", "scan.status", "scan.latest"];

    /// <summary>
    /// Lectura detallada (inventario, líneas de comando, rutas de todos los usuarios). Requiere elevación salvo que
    /// un administrador active AllowUnelevatedReads.
    /// </summary>
    public static readonly HashSet<string> ReadOperations =
        ["scan.list", "scan.get", "findings.list", "entity.detail", "inventory", "diff", "plan", "timeline", "action.list", "allowlist.list", "config.get"];

    // Todo lo demás (escanear, cancelar, responder preguntas, allowlist, acciones, ajustes, herramientas, feeds)
    // requiere un proceso elevado: un malware sin privilegios no puede ni marcarse como "reconocido" ni ordenar acciones.
    // scan.start también: evita que un proceso sin privilegios dispare escaneos en loop (consumo) o los use de oráculo.

    /// <summary>Tamaño máximo de un mensaje (protege al servicio de agotamiento de memoria).</summary>
    public const int MaxMessageChars = 1_000_000;
}

public sealed class IpcRequest
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Op { get; set; } = "";
    public JsonObject? Args { get; set; }

    public string? Str(string name) => Args?[name]?.GetValueKind() == JsonValueKind.String ? Args[name]!.GetValue<string>() : Args?[name]?.ToString();
    public bool Bool(string name) => Args?[name]?.GetValueKind() == JsonValueKind.True;
    public long? Long(string name) => Args?[name] is JsonValue v && v.TryGetValue<long>(out var l) ? l : long.TryParse(Str(name), out var p) ? p : null;
}

public sealed class IpcResponse
{
    public string? Id { get; set; }
    public bool Ok { get; set; }
    public JsonNode? Data { get; set; }
    public string? Error { get; set; }
    /// <summary>Para mensajes push: progress | scan_done | scan_error | scan_cancelled.</summary>
    public string? Event { get; set; }
}
