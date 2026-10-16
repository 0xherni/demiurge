using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Util;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Demiurge.Core.Rules;

public sealed class HeuristicDefinition
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public int Weight { get; set; }
    public Severity Severity { get; set; }
    public List<string> Attack { get; set; } = new();
    public string Category { get; set; } = "";
    public string Phase { get; set; } = "v1";
    public bool Enabled { get; set; } = true;
    public string Template { get; set; } = "";
    public string Action { get; set; } = "";
    public Dictionary<string, object> Params { get; set; } = new();
    public QuestionDefinition? Question { get; set; }

    public List<string> List(string key) =>
        Params.TryGetValue(key, out var v) && v is List<object> l ? l.Select(x => x?.ToString() ?? "").ToList() : new();

    public int Int(string key, int fallback) =>
        Params.TryGetValue(key, out var v) && int.TryParse(v?.ToString(), out var i) ? i : fallback;

    public double Double(string key, double fallback) =>
        Params.TryGetValue(key, out var v) && double.TryParse(v?.ToString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) ? d : fallback;

    /// <summary>Mapa clave → lista (p.ej. patterns de H-07).</summary>
    public Dictionary<string, List<string>> Map(string key)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        if (Params.TryGetValue(key, out var v) && v is Dictionary<object, object> d)
            foreach (var (k, val) in d)
                result[k.ToString()!] = val is List<object> l ? l.Select(x => x?.ToString() ?? "").ToList() : [val?.ToString() ?? ""];
        return result;
    }
}

public sealed class QuestionDefinition
{
    public string Id { get; set; } = "";
    public string Text { get; set; } = "";
    public List<UserQuestionOption> Options { get; set; } = new();
}

public sealed class ScoringParameters
{
    public int ReviewMin { get; set; } = 20;
    public int DangerMin { get; set; } = 60;
    public double AccumulationBonus { get; set; } = 0.20;
    public int AccumulationMinCategories { get; set; } = 3;
    /// <summary>Heurísticas que la allowlist dura ignora.</summary>
    public List<string> HardAllowlistIgnores { get; set; } = ["H-03", "H-04", "H-14"];
    /// <summary>Heurísticas que NUNCA se ignoran (un binario legítimo puede estar comprometido o abusado).</summary>
    public List<string> NeverIgnore { get; set; } = ["H-01", "H-02", "H-26", "H-27"];
}

/// <summary>Reglas declarativas (YAML) cargadas en runtime: embebidas o desde %ProgramData%\Demiurge\rules.</summary>
public sealed class RuleSet
{
    public string Version { get; set; } = "";
    public List<HeuristicDefinition> Heuristics { get; set; } = new();
    public ScoringParameters Scoring { get; set; } = new();

    public HeuristicDefinition? this[string id] => Heuristics.FirstOrDefault(h => h.Id == id && h.Enabled);

    public static RuleSet Parse(string yaml)
    {
        var d = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
        return d.Deserialize<RuleSet>(yaml) ?? new RuleSet();
    }

    public static RuleSet Load()
    {
        // Sin crear carpetas: sin permisos (CLI sin elevar) la carpeta de datos no se puede ni abrir, y se usan las reglas incluidas.
        var external = Path.Combine(DemiurgePaths.Root, "rules", "heuristics.yaml");
        if (File.Exists(external) && Security.DataDirectoryLockdown.CanTrust(external))
        {
            try { return Parse(File.ReadAllText(external)); }
            catch
            {
                // YAML editado con errores: volvemos al embebido para no dejar al usuario sin protección.
            }
        }
        return Parse(EmbeddedResource.Read("heuristics.yaml"));
    }
}
