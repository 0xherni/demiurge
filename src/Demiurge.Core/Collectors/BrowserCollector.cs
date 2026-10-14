using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-22: navegadores Chromium (Chrome, Edge, Brave, Opera, Vivaldi) y Firefox, en todos los perfiles
/// de todos los usuarios: extensiones, buscador, página de inicio, permisos de notificación y políticas.
/// </summary>
public sealed class BrowserCollector : ICollector
{
    public string Id => "COL-22";
    public string Name => "Navegadores";
    public int Order => 20;

    private sealed record ChromiumBrowser(string Name, string RelativePath, bool Roaming, bool SingleProfile, string PolicyKey);

    private static readonly ChromiumBrowser[] Chromiums =
    [
        new("Chrome", @"Google\Chrome\User Data", false, false, @"SOFTWARE\Policies\Google\Chrome"),
        new("Edge", @"Microsoft\Edge\User Data", false, false, @"SOFTWARE\Policies\Microsoft\Edge"),
        new("Brave", @"BraveSoftware\Brave-Browser\User Data", false, false, @"SOFTWARE\Policies\BraveSoftware\Brave"),
        new("Vivaldi", @"Vivaldi\User Data", false, false, @"SOFTWARE\Policies\Vivaldi"),
        new("Opera", @"Opera Software\Opera Stable", true, true, @"SOFTWARE\Policies\Opera Software\Opera"),
        new("Opera GX", @"Opera Software\Opera GX Stable", true, true, @"SOFTWARE\Policies\Opera Software\Opera GX"),
    ];

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var extensions = new List<BrowserExtension>();
        var settings = new List<BrowserSettingInfo>();

        foreach (var profile in UserProfiles.All())
        {
            ct.ThrowIfCancellationRequested();
            foreach (var b in Chromiums)
            {
                var root = Path.Combine(b.Roaming ? UserProfiles.RoamingAppData(profile) : UserProfiles.LocalAppData(profile), b.RelativePath);
                if (!Directory.Exists(root)) continue;
                var profileDirs = b.SingleProfile
                    ? [root]
                    : Directory.EnumerateDirectories(root).Where(d => File.Exists(Path.Combine(d, "Preferences")));
                foreach (var dir in profileDirs)
                {
                    try { ReadChromiumProfile(b.Name, profile.UserName, dir, extensions, settings); }
                    catch (Exception ex) { ctx.Logger.LogDebugSafe($"{b.Name} {dir}: {ex.Message}"); }
                }
            }

            var ffRoot = Path.Combine(UserProfiles.RoamingAppData(profile), @"Mozilla\Firefox\Profiles");
            if (Directory.Exists(ffRoot))
            {
                foreach (var dir in Directory.EnumerateDirectories(ffRoot))
                {
                    try { ReadFirefoxProfile(profile.UserName, dir, extensions, settings); }
                    catch (Exception ex) { ctx.Logger.LogDebugSafe($"Firefox {dir}: {ex.Message}"); }
                }
            }
        }

        ReadPolicies(settings);

        ctx.Snapshot.AddRange(ctx.Snapshot.Extensions, extensions);
        ctx.Snapshot.AddRange(ctx.Snapshot.BrowserSettings, settings);
        return Task.FromResult(CollectorResult.Of(extensions.Count + settings.Count));
    }

    // ---------------- Chromium ----------------

    private static void ReadChromiumProfile(string browser, string user, string dir, List<BrowserExtension> extensions, List<BrowserSettingInfo> settings)
    {
        var profileName = Path.GetFileName(dir);
        var prefs = LoadJson(Path.Combine(dir, "Preferences"));
        var secure = LoadJson(Path.Combine(dir, "Secure Preferences"));
        if (prefs is null && secure is null) return;

        // Nombre visible del perfil
        if (prefs?["profile"]?["name"]?.GetValue<string>() is { Length: > 0 } pn) profileName = $"{profileName} ({pn})";

        // Extensiones: en Secure Preferences (Chrome moderno) o Preferences (versiones viejas / otros forks).
        var extSettings = (secure?["extensions"]?["settings"] as JsonObject) ?? (prefs?["extensions"]?["settings"] as JsonObject);
        if (extSettings is not null)
        {
            foreach (var (id, node) in extSettings)
            {
                if (node is not JsonObject e) continue;
                int location = e["location"]?.GetValueKind() == JsonValueKind.Number ? e["location"]!.GetValue<int>() : 0;
                // 5 = COMPONENT, 10 = EXTERNAL_COMPONENT: internas del navegador.
                if (location is 5 or 10) continue;

                var manifest = e["manifest"] as JsonObject ?? LoadManifest(dir, id, e["path"]?.GetValue<string>());
                if (manifest is null && e["path"] is null) continue;

                var name = manifest?["name"]?.GetValue<string>() ?? id;
                if (name.StartsWith("__MSG_", StringComparison.Ordinal))
                    name = ResolveMessage(dir, id, e["path"]?.GetValue<string>(), manifest, name) ?? name;

                bool fromStore = e["from_webstore"]?.GetValue<bool>() == true;
                var updateUrl = manifest?["update_url"]?.GetValue<string>();
                string origin = location switch
                {
                    4 or 8 => "sideload",          // UNPACKED / COMMAND_LINE
                    7 or 9 => "policy",            // EXTERNAL_POLICY(_DOWNLOAD)
                    2 or 3 or 6 => updateUrl is not null && IsStoreUrl(updateUrl) ? "store" : "sideload", // externas
                    1 => fromStore || (updateUrl is not null && IsStoreUrl(updateUrl)) ? "store" : "sideload",
                    _ => fromStore ? "store" : "unknown",
                };

                var perms = new List<string>();
                foreach (var key in new[] { "permissions", "host_permissions", "optional_permissions" })
                    if (manifest?[key] is JsonArray arr)
                        perms.AddRange(arr.Select(p => p?.ToString() ?? "").Where(p => p.Length > 0));
                if (manifest?["content_scripts"] is JsonArray cs)
                    perms.AddRange(cs.SelectMany(s => (s?["matches"] as JsonArray)?.Select(m => m?.ToString() ?? "") ?? []).Where(m => m.Length > 0).Distinct());

                bool enabled = e["state"]?.GetValueKind() == JsonValueKind.Number
                    ? e["state"]!.GetValue<int>() == 1
                    : e["disable_reasons"] is null || (e["disable_reasons"]?.GetValueKind() == JsonValueKind.Number && e["disable_reasons"]!.GetValue<int>() == 0)
                      || (e["disable_reasons"] is JsonArray dr && dr.Count == 0);

                extensions.Add(new BrowserExtension
                {
                    Browser = browser,
                    Profile = profileName,
                    User = user,
                    Id = id,
                    Name = name,
                    Version = manifest?["version"]?.GetValue<string>(),
                    Permissions = perms.Distinct().ToList(),
                    Origin = origin,
                    Enabled = enabled,
                    UpdateUrl = updateUrl,
                    ProfilePath = dir,
                });
            }
        }

        // Buscador predeterminado
        var search = prefs?["default_search_provider_data"]?["template_url_data"];
        var searchUrl = search?["url"]?.GetValue<string>();
        if (!string.IsNullOrEmpty(searchUrl))
            settings.Add(Setting(browser, user, profileName, dir, "search_engine", searchUrl));

        // Página de inicio / URLs de arranque
        if (prefs?["homepage"]?.GetValue<string>() is { Length: > 0 } home && prefs?["homepage_is_newtabpage"]?.GetValue<bool>() != true)
            settings.Add(Setting(browser, user, profileName, dir, "homepage", home));
        if (prefs?["session"]?["startup_urls"] is JsonArray startup && prefs["session"]?["restore_on_startup"]?.GetValue<int>() == 4)
            foreach (var u in startup)
                if (u?.ToString() is { Length: > 0 } url)
                    settings.Add(Setting(browser, user, profileName, dir, "startup_url", url));

        // Permisos de notificación (setting 1 = permitido)
        if (prefs?["profile"]?["content_settings"]?["exceptions"]?["notifications"] is JsonObject notif)
        {
            foreach (var (pattern, value) in notif)
            {
                if (value?["setting"]?.GetValueKind() == JsonValueKind.Number && value["setting"]!.GetValue<int>() == 1)
                    settings.Add(Setting(browser, user, profileName, dir, "notifications", pattern.Split(',')[0]));
            }
        }
    }

    private static bool IsStoreUrl(string url) =>
        url.Contains("clients2.google.com/service/update2/crx", StringComparison.OrdinalIgnoreCase) ||
        url.Contains("edge.microsoft.com/extensionwebstorebase", StringComparison.OrdinalIgnoreCase) ||
        url.Contains("extension-updates.opera.com", StringComparison.OrdinalIgnoreCase);

    private static JsonObject? LoadManifest(string profileDir, string id, string? path)
    {
        var extDir = path is not null && Path.IsPathRooted(path) ? path : Path.Combine(profileDir, "Extensions", id);
        if (!Directory.Exists(extDir)) return null;
        var manifestPath = Path.Combine(extDir, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            var versionDir = Directory.EnumerateDirectories(extDir).OrderByDescending(d => d).FirstOrDefault();
            if (versionDir is null) return null;
            manifestPath = Path.Combine(versionDir, "manifest.json");
        }
        return LoadJson(manifestPath);
    }

    private static string? ResolveMessage(string profileDir, string id, string? path, JsonObject? manifest, string msg)
    {
        try
        {
            var extDir = path is not null && Path.IsPathRooted(path) ? path : Path.Combine(profileDir, "Extensions", id);
            if (!Directory.Exists(extDir)) return null;
            var baseDir = File.Exists(Path.Combine(extDir, "manifest.json"))
                ? extDir
                : Directory.EnumerateDirectories(extDir).OrderByDescending(d => d).FirstOrDefault();
            if (baseDir is null) return null;
            var locale = manifest?["default_locale"]?.GetValue<string>() ?? "en";
            var key = msg[6..^2];
            foreach (var loc in new[] { "es", "es_419", locale, "en" })
            {
                var messages = LoadJson(Path.Combine(baseDir, "_locales", loc, "messages.json"));
                if (messages is null) continue;
                foreach (var (k, v) in messages)
                    if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase))
                        return v?["message"]?.GetValue<string>();
            }
        }
        catch
        {
            // ignorar
        }
        return null;
    }

    // ---------------- Firefox ----------------

    private static void ReadFirefoxProfile(string user, string dir, List<BrowserExtension> extensions, List<BrowserSettingInfo> settings)
    {
        var profileName = Path.GetFileName(dir);
        var json = LoadJson(Path.Combine(dir, "extensions.json"));
        if (json?["addons"] is JsonArray addons)
        {
            foreach (var a in addons.OfType<JsonObject>())
            {
                if (a["type"]?.GetValue<string>() != "extension") continue;
                var location = a["location"]?.GetValue<string>() ?? "";
                // Componentes internos de Firefox (app-builtin, app-builtin-addons, app-system-defaults, app-system-addons).
                if (location.StartsWith("app-builtin", StringComparison.Ordinal) || location.StartsWith("app-system", StringComparison.Ordinal)) continue;
                var perms = new List<string>();
                if (a["userPermissions"]?["permissions"] is JsonArray p) perms.AddRange(p.Select(x => x?.ToString() ?? ""));
                if (a["userPermissions"]?["origins"] is JsonArray o) perms.AddRange(o.Select(x => x?.ToString() ?? ""));
                var source = a["sourceURI"]?.GetValue<string>() ?? "";
                int signed = a["signedState"]?.GetValueKind() == JsonValueKind.Number ? a["signedState"]!.GetValue<int>() : 0;
                string origin = location == "app-profile"
                    ? (source.Contains("addons.mozilla.org", StringComparison.OrdinalIgnoreCase) || signed >= 2 ? "store" : "sideload")
                    : location.Contains("policy") ? "policy" : "sideload";

                extensions.Add(new BrowserExtension
                {
                    Browser = "Firefox",
                    Profile = profileName,
                    User = user,
                    Id = a["id"]?.GetValue<string>() ?? "",
                    Name = a["defaultLocale"]?["name"]?.GetValue<string>() ?? a["id"]?.GetValue<string>() ?? "",
                    Version = a["version"]?.GetValue<string>(),
                    Permissions = perms.Where(x => x.Length > 0).Distinct().ToList(),
                    Origin = origin,
                    Enabled = a["active"]?.GetValue<bool>() == true,
                    ProfilePath = dir,
                });
            }
        }

        var prefsPath = Path.Combine(dir, "prefs.js");
        if (File.Exists(prefsPath))
        {
            foreach (var line in ReadShared(prefsPath).Split('\n'))
            {
                if (TryPref(line, "browser.startup.homepage", out var home) && !home.StartsWith("about:", StringComparison.OrdinalIgnoreCase) && !home.StartsWith("chrome:", StringComparison.OrdinalIgnoreCase))
                    foreach (var h in home.Split('|')) settings.Add(Setting("Firefox", user, profileName, dir, "homepage", h));
                if (TryPref(line, "browser.urlbar.placeholderName", out var engine))
                    settings.Add(Setting("Firefox", user, profileName, dir, "search_engine", engine));
                if (TryPref(line, "network.proxy.http", out var proxy) && proxy.Length > 0)
                    settings.Add(Setting("Firefox", user, profileName, dir, "proxy", proxy));
            }
        }

        // Permisos de notificación en permissions.sqlite (copiamos el archivo: Firefox lo tiene bloqueado).
        var perm = Path.Combine(dir, "permissions.sqlite");
        if (File.Exists(perm))
        {
            var tmp = Path.Combine(Path.GetTempPath(), $"demiurge_ffperm_{Guid.NewGuid():N}.sqlite");
            try
            {
                File.Copy(perm, tmp, true);
                using var conn = new SqliteConnection($"Data Source={tmp};Mode=ReadOnly;Pooling=False");
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT origin FROM moz_perms WHERE type = 'desktop-notification' AND permission = 1";
                using var r = cmd.ExecuteReader();
                while (r.Read()) settings.Add(Setting("Firefox", user, profileName, dir, "notifications", r.GetString(0)));
            }
            catch
            {
                // esquema distinto
            }
            finally
            {
                try { File.Delete(tmp); } catch { }
            }
        }
    }

    private static bool TryPref(string line, string name, out string value)
    {
        value = "";
        var prefix = $"user_pref(\"{name}\",";
        if (!line.StartsWith(prefix, StringComparison.Ordinal)) return false;
        value = line[prefix.Length..].Trim().TrimEnd(';').TrimEnd(')').Trim().Trim('"');
        return true;
    }

    // ---------------- Políticas forzadas por registro ----------------

    private static void ReadPolicies(List<BrowserSettingInfo> settings)
    {
        foreach (var b in Chromiums)
        {
            ReadPolicyKey(Registry.LocalMachine, "HKLM", b, settings);
            foreach (var (_, user, root) in UserProfiles.UserHives())
                using (root) ReadPolicyKey(root, user, b, settings);
        }
        using var ff = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Mozilla\Firefox");
        if (ff is not null)
            foreach (var v in ff.GetValueNames())
                settings.Add(new BrowserSettingInfo { Browser = "Firefox", Profile = "*", User = "HKLM", Setting = "policy", Value = $"{v}={ff.GetValue(v)}" });
    }

    private static void ReadPolicyKey(RegistryKey hive, string user, ChromiumBrowser b, List<BrowserSettingInfo> settings)
    {
        using var k = hive.OpenSubKey(b.PolicyKey);
        if (k is null) return;
        string[] interesting = ["HomepageLocation", "DefaultSearchProviderSearchURL", "DefaultSearchProviderName", "RestoreOnStartupURLs", "ProxyServer", "ProxyPacUrl", "NewTabPageLocation"];
        foreach (var v in k.GetValueNames().Where(v => interesting.Contains(v, StringComparer.OrdinalIgnoreCase)))
            settings.Add(new BrowserSettingInfo { Browser = b.Name, Profile = "*", User = user, Setting = "policy", Value = $"{v}={k.GetValue(v)}" });
        foreach (var listName in new[] { "ExtensionInstallForcelist", "RestoreOnStartupURLs" })
        {
            using var list = k.OpenSubKey(listName);
            if (list is null) continue;
            foreach (var v in list.GetValueNames())
                settings.Add(new BrowserSettingInfo { Browser = b.Name, Profile = "*", User = user, Setting = "policy", Value = $"{listName}={list.GetValue(v)}" });
        }
    }

    // ---------------- helpers ----------------

    private static BrowserSettingInfo Setting(string browser, string user, string profile, string dir, string name, string value) =>
        new() { Browser = browser, User = user, Profile = profile, ProfilePath = dir, Setting = name, Value = value };

    private static string ReadShared(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var sr = new StreamReader(fs);
        return sr.ReadToEnd();
    }

    internal static JsonObject? LoadJson(string path)
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length > 32L * 1024 * 1024) return null; // archivos absurdos: no procesar como SYSTEM
            return JsonNode.Parse(ReadShared(path), documentOptions: new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip }) as JsonObject;
        }
        catch
        {
            return null;
        }
    }
}

internal static class LoggerExtensions
{
    public static void LogDebugSafe(this Microsoft.Extensions.Logging.ILogger logger, string message)
    {
        try { Microsoft.Extensions.Logging.LoggerExtensions.LogDebug(logger, "{Message}", message); } catch { }
    }
}
