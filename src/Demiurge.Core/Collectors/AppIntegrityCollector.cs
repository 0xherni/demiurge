using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-30: integridad de aplicaciones que los ladrones de cuentas modifican para quedarse adentro.
///
/// Discord (estable, PTB, Canary, Development): en una instalación limpia,
/// %LOCALAPPDATA%\Discord\app-*\modules\discord_desktop_core-*\discord_desktop_core\index.js tiene UNA línea:
///     module.exports = require('./core.asar');
/// Los "token grabbers" le agregan código que roba la sesión cada vez que Discord se abre, y eso sobrevive a borrar el
/// programa que lo infectó. BetterDiscord también modifica el archivo, pero de una forma conocida.
/// </summary>
public sealed class AppIntegrityCollector : ICollector
{
    public string Id => "COL-30";
    public string Name => "Integridad de aplicaciones";
    public int Order => 20;

    private static readonly string[] DiscordFlavors = ["Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment"];
    private const long MaxIndexBytes = 8 * 1024 * 1024;

    private static readonly Regex OriginalLine = new(@"^module\.exports\s*=\s*require\(\s*['""]\./core\.asar['""]\s*\)\s*;?$", RegexOptions.NonBacktracking);
    private static readonly Regex BetterDiscordLine = new(@"^require\(\s*['""][^'""]*betterdiscord[^'""]*\.asar['""]\s*\)\s*;?$", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);

    /// <summary>Señales dentro del código agregado: a dónde manda los datos y qué toca.</summary>
    private static readonly (string Name, Regex Rx)[] IndicatorPatterns =
    [
        ("webhook de Discord", new(@"discord(app)?\.com/api/webhooks", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)),
        ("envía datos a internet", new(@"https?://", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)),
        ("lee el token de la sesión", new(@"token", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)),
        ("ejecuta comandos", new(@"child_process|\bexec(Sync)?\s*\(|\bspawn\s*\(", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)),
        ("código ofuscado", new(@"\beval\s*\(|_0x[0-9a-f]{4,}|atob\s*\(|Buffer\.from\([^)]*base64", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)),
        ("lee contraseñas o tarjetas", new(@"password|creditcard|card_number|\bcvc\b|billing", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)),
    ];

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var list = new List<AppIntegrityInfo>();
        var warnings = new List<string>();
        foreach (var profile in UserProfiles.All())
        {
            foreach (var flavor in DiscordFlavors)
            {
                ct.ThrowIfCancellationRequested();
                var root = Path.Combine(profile.Path, "AppData", "Local", flavor);
                try
                {
                    if (!Directory.Exists(root)) continue;
                    foreach (var appDir in Directory.EnumerateDirectories(root, "app-*"))
                    {
                        var modules = Path.Combine(appDir, "modules");
                        if (!Directory.Exists(modules)) continue;
                        foreach (var core in Directory.EnumerateDirectories(modules, "discord_desktop_core*"))
                        {
                            var index = Path.Combine(core, "discord_desktop_core", "index.js");
                            if (!File.Exists(index)) continue;
                            var fi = new FileInfo(index);
                            // Un enlace o junction no es una instalación normal: no lo seguimos.
                            if (fi.Attributes.HasFlag(FileAttributes.ReparsePoint) || fi.Length > MaxIndexBytes) continue;
                            var bytes = File.ReadAllBytes(index);
                            var item = Evaluate(flavor, Encoding.UTF8.GetString(bytes).TrimStart('﻿'));
                            item.Path = index;
                            item.User = profile.UserName;
                            item.Size = bytes.Length;
                            item.Modified = fi.LastWriteTime;
                            item.Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                            list.Add(item);
                        }
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                {
                    warnings.Add($"No se pudo revisar {flavor} de {profile.UserName}");
                }
            }
        }
        ctx.Snapshot.AddRange(ctx.Snapshot.AppIntegrity, list);
        return Task.FromResult(new CollectorResult { ItemCount = list.Count, Warnings = warnings });
    }

    /// <summary>Clasifica el contenido del index.js de Discord.</summary>
    internal static AppIntegrityInfo Evaluate(string flavor, string content)
    {
        var item = new AppIntegrityInfo { App = flavor switch { "DiscordPTB" => "Discord PTB", "DiscordCanary" => "Discord Canary", "DiscordDevelopment" => "Discord Development", _ => "Discord" } };
        var lines = content.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith("//", StringComparison.Ordinal)).ToList();
        var extra = lines.Where(l => !OriginalLine.IsMatch(l)).ToList();
        bool hasOriginal = lines.Any(l => OriginalLine.IsMatch(l));

        if (extra.Count == 0 && hasOriginal)
        {
            item.Status = "original";
            return item;
        }
        if (hasOriginal && extra.All(l => BetterDiscordLine.IsMatch(l)))
        {
            item.Status = "mod";
            item.ModName = "BetterDiscord";
            return item;
        }

        item.Status = "modified";
        var added = string.Join("\n", extra);
        foreach (var (name, rx) in IndicatorPatterns)
            if (rx.IsMatch(added)) item.Indicators.Add(name);
        if (!hasOriginal) item.Indicators.Add("reemplaza el arranque normal de Discord");
        var flat = Regex.Replace(added, @"\s+", " ");
        item.Excerpt = flat.Length > 240 ? flat[..237] + "…" : flat;
        return item;
    }

    /// <summary>Contenido original del index.js (para la acción "Reparar Discord").</summary>
    public const string DiscordOriginalIndex = "module.exports = require('./core.asar');";
}
