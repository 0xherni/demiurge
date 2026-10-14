using System.Text.Json;
using Demiurge.Core.Knowledge;

namespace Demiurge.Core.Text;

/// <summary>
/// Textos de la interfaz (i18n desde el inicio). Base: español rioplatense neutro-amable.
/// Para agregar un idioma: Resources/strings.{lang}.json con las mismas claves.
/// </summary>
public sealed class TextCatalog
{
    private readonly Dictionary<string, string> _strings;
    private readonly Dictionary<string, string> _fallback;

    public string Language { get; }

    public TextCatalog(string language = "es-AR")
    {
        Language = language;
        _fallback = Load("es-AR") ?? new();
        _strings = language == "es-AR" ? _fallback : Load(language) ?? _fallback;
    }

    private static Dictionary<string, string>? Load(string lang)
    {
        try { return JsonSerializer.Deserialize<Dictionary<string, string>>(EmbeddedResource.Read($"strings.{lang}.json")); }
        catch { return null; }
    }

    public string this[string key] => Get(key);

    public string Get(string key, params (string name, object? value)[] args)
    {
        var s = _strings.GetValueOrDefault(key) ?? _fallback.GetValueOrDefault(key) ?? key;
        foreach (var (n, v) in args) s = s.Replace("{" + n + "}", v?.ToString() ?? "");
        return s;
    }

    public bool Has(string key) => _strings.ContainsKey(key) || _fallback.ContainsKey(key);
}
