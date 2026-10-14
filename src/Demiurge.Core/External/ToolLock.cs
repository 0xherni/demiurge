using System.Text.Json;
using Demiurge.Core.Knowledge;

namespace Demiurge.Core.External;

/// <summary>Versiones y hashes fijados de las herramientas que vienen con el instalador (Resources/tools.lock.json).</summary>
public static class ToolLock
{
    public sealed class Entry
    {
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public string Url { get; set; } = "";
        public string ZipSha256 { get; set; } = "";
        public string Dir { get; set; } = "";
        public string Exe { get; set; } = "";
        public string ExeSha256 { get; set; } = "";
        public string License { get; set; } = "";
        public string LicenseUrl { get; set; } = "";
        /// <summary>Copiar todo el contenido del zip (Hayabusa necesita sus reglas embebidas junto al exe).</summary>
        public bool CopyAll { get; set; }
        /// <summary>Código fuente de la versión exacta (las licencias GPL/AGPL exigen ofrecerlo).</summary>
        public string? SourceUrl { get; set; }
    }

    private sealed class LockFile
    {
        public Dictionary<string, Entry> Tools { get; set; } = new();
    }

    private static readonly Lazy<Dictionary<string, Entry>> Entries = new(() =>
        JsonSerializer.Deserialize<LockFile>(EmbeddedResource.Read("tools.lock.json"), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })?.Tools
        ?? new Dictionary<string, Entry>());

    public static Entry? Get(string? id) => id is not null && Entries.Value.TryGetValue(id, out var e) ? e : null;
}
