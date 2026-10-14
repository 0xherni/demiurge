using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Demiurge.Core.Intel;
using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Rules;

/// <summary>Todo lo que una heurística necesita para evaluar y emitir findings.</summary>
public sealed class RuleContext
{
    public required ScanSnapshot Snapshot { get; init; }
    public ScanSnapshot? Previous { get; init; }
    public required RuleSet Rules { get; init; }
    public required KnowledgeBase Kb { get; init; }
    public required FeedStore Feeds { get; init; }
    public Dictionary<string, UserAnswer> Answers { get; init; } = new();

    public List<Finding> Findings { get; } = new();

    private Dictionary<int, ProcessInfo>? _byPid;
    public Dictionary<int, ProcessInfo> ProcessesByPid =>
        _byPid ??= Snapshot.Processes.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.OrderBy(p => p.EndTime is null ? 0 : 1).ThenByDescending(p => p.StartTime).First());

    private Dictionary<string, string?>? _pathToBinary;
    /// <summary>Clave de binario a partir de una ruta (para conexiones, que sólo traen PID/ruta).</summary>
    public string? BinaryKeyForPath(string? path)
    {
        if (path is null) return null;
        _pathToBinary ??= Snapshot.Binaries.Values
            .GroupBy(b => b.Path, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => (string?)g.First().Key, StringComparer.OrdinalIgnoreCase);
        return _pathToBinary.GetValueOrDefault(path);
    }

    /// <summary>
    /// Allowlist dura (06_Scoring): firmado por Microsoft con firma válida, hash en CIRCL hashlookup,
    /// o entrada benigna de la KB con firmante/ubicación esperados.
    /// </summary>
    public bool IsHardAllowlisted(BinaryInfo? b) =>
        b is not null && (b.Signature?.IsMicrosoft == true || b.IsKnownGood || Kb.MatchBinary(b)?.Trusted == true || IsSelf(b));

    /// <summary>Los ejecutables de la propia app (demiurge.exe / DemiurgeService.exe en su carpeta de instalación).</summary>
    private static bool IsSelf(BinaryInfo b) =>
        b.Path.StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase) &&
        Path.GetFileName(b.Path) is var n && (n.Equals("demiurge.exe", StringComparison.OrdinalIgnoreCase) || n.Equals("DemiurgeService.exe", StringComparison.OrdinalIgnoreCase));

    public bool IsUnsigned(BinaryInfo? b) => b is not null && b.Exists && b.Signature is not null && !b.Signature.IsValid;

    /// <summary>
    /// Para binarios compartidos del sistema (powershell, rundll32, svchost firmados por Microsoft) la señal se
    /// cuelga del proceso/persistencia, no del binario: si no, todo uso de PowerShell sumaría sobre la misma entidad.
    /// </summary>
    public string ScoringKeyFor(string? binaryKey, string fallbackKey)
    {
        var b = Snapshot.GetBinary(binaryKey);
        if (b is null) return fallbackKey;
        return b.Signature?.IsMicrosoft == true ? fallbackKey : b.Key;
    }

    public Finding Emit(HeuristicDefinition def, IEntity entity, string scoringKey, Dictionary<string, string?> values, JsonObject? raw = null, int? weightOverride = null)
    {
        var f = new Finding
        {
            HeuristicId = def.Id,
            HeuristicName = def.Name,
            EntityKind = entity.Kind,
            EntityKey = entity.Key,
            EntityName = entity.DisplayName,
            ScoringKey = scoringKey,
            Weight = weightOverride ?? def.Weight,
            BaseWeight = weightOverride ?? def.Weight,
            Severity = def.Severity,
            Category = def.Category,
            AttackIds = def.Attack.ToList(),
            Explanation = Render(def.Template, values),
            RecommendedAction = def.Action,
            RawData = raw ?? new JsonObject(),
        };
        if (def.Question is not null)
        {
            f.Question = new UserQuestion
            {
                QuestionId = def.Question.Id,
                Text = Render(def.Question.Text, values),
                Options = def.Question.Options.ToList(),
            };
        }
        Findings.Add(f);
        return f;
    }

    public static string Render(string template, Dictionary<string, string?> values)
    {
        var s = template;
        foreach (var (k, v) in values) s = s.Replace("{" + k + "}", v ?? "?");
        return Regex.Replace(s, @"\{[a-z_]+\}", "?");
    }

    public static bool IsPublicIp(string? ip)
    {
        if (!IPAddress.TryParse(ip, out var a)) return false;
        if (IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any)) return false;
        if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (a.IsIPv4MappedToIPv6) return IsPublicIp(a.MapToIPv4().ToString());
            return !(a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast || a.IsIPv6UniqueLocal);
        }
        var b = a.GetAddressBytes();
        return !(b[0] == 10 || b[0] == 127 || b[0] == 0 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                 (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||
                 b[0] >= 224);
    }

    public static JsonObject Raw(params (string key, object? value)[] items)
    {
        var o = new JsonObject();
        foreach (var (k, v) in items)
            o[k] = v switch
            {
                null => null,
                JsonNode n => n,
                IEnumerable<string> list when v is not string => new JsonArray(list.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()),
                _ => JsonValue.Create(v.ToString()),
            };
        return o;
    }

    public static string FolderLabel(string? path) => PathClassifier.UserWritableFolder(path) ?? Path.GetDirectoryName(path ?? "") ?? "?";
}
