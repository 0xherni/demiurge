using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Microsoft.Win32.TaskScheduler;
using Demiurge.Core.Model;
using Demiurge.Core.Native;
using Demiurge.Core.Storage;
using Demiurge.Core.Util;

namespace Demiurge.Core.Actions;

public sealed class ActionRequest
{
    public string Action { get; set; } = "";
    /// <summary>Entidad sobre la que actuar (clave de entidad o de scoring).</summary>
    public string EntityKey { get; set; } = "";
    /// <summary>Las acciones exigen confirmación explícita del usuario.</summary>
    public bool Confirmed { get; set; }
    public string? Note { get; set; }
}

public sealed class ActionResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public string? ActionId { get; set; }
    public bool Reversible { get; set; }
}

/// <summary>
/// Acciones disponibles desde la app (vía servicio). Toda acción guarda un backup y se puede revertir,
/// salvo finalizar un proceso (que se indica explícitamente).
/// </summary>
public sealed class ActionService
{
    private readonly DemiurgeDb _db;
    private readonly ILogger _logger;

    public ActionService(DemiurgeDb db, ILogger logger)
    {
        _db = db;
        _logger = logger;
    }

    public ActionResult Execute(ActionRequest req, ScanSnapshot snapshot)
    {
        if (!req.Confirmed)
            return new ActionResult { Message = "La acción necesita confirmación del usuario." };
        try
        {
            var result = req.Action switch
            {
                "disable_startup" => DisableStartup(req, snapshot),
                "remove_wmi" => RemoveWmi(req, snapshot),
                "remove_ifeo" => DisableStartup(req, snapshot),
                "kill_process" => KillProcess(req, snapshot),
                "quarantine" => Quarantine(req, snapshot),
                "remove_exclusion" => RemoveExclusion(req, snapshot),
                "restore_hosts" => RestoreHosts(),
                "repair_app" => RepairApp(req, snapshot),
                "restore_proxy" => RestoreProxy(),
                "restore_browser" => RestoreBrowser(req, snapshot),
                "remove_extension" => RemoveExtension(req, snapshot),
                "remove_notifications" => RemoveNotifications(req, snapshot),
                "disable_account" => DisableAccount(req, snapshot),
                "remove_certificate" => RemoveCertificate(req, snapshot),
                "allowlist" => Allowlist(req, snapshot),
                _ => new ActionResult { Message = $"Acción desconocida: {req.Action}" },
            };
            _logger.LogInformation("Acción {Action} sobre {Entity}: {Ok} {Message}", req.Action, req.EntityKey, result.Success, result.Message);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Acción {Action} falló", req.Action);
            return new ActionResult { Message = "No se pudo completar la acción: " + ex.Message };
        }
    }

    private ActionResult Record(string type, string target, string description, object backup, bool reversible = true)
    {
        var rec = new ActionRecord
        {
            Type = type,
            Target = target,
            Description = description,
            Backup = JsonSerializer.Serialize(backup, DemiurgeDb.Json),
        };
        _db.SaveAction(rec);
        return new ActionResult { Success = true, Message = description, ActionId = rec.Id, Reversible = reversible };
    }

    // ---------------------------------------------------------------- Arranque

    private IEnumerable<PersistenceItem> PersistenceFor(string key, ScanSnapshot s) =>
        s.Persistence.Where(p => p.Key == key || p.BinaryKey == key);

    private ActionResult DisableStartup(ActionRequest req, ScanSnapshot s)
    {
        var items = PersistenceFor(req.EntityKey, s).ToList();
        if (items.Count == 0) return new ActionResult { Message = "No encontramos esa entrada de arranque." };
        var messages = new List<string>();
        string? lastId = null;
        foreach (var item in items)
        {
            var r = DisableOne(item);
            messages.Add(r.Message);
            lastId = r.ActionId ?? lastId;
        }
        return new ActionResult { Success = true, Message = string.Join(" ", messages), ActionId = lastId, Reversible = true };
    }

    private ActionResult DisableOne(PersistenceItem item)
    {
        switch (item.Type)
        {
            case PersistenceType.RunKey or PersistenceType.RunOnce or PersistenceType.Ifeo:
            {
                var (hive, sub) = OpenHive(item.Location);
                var valueName = item.Type == PersistenceType.Ifeo ? (item.Extra.GetValueOrDefault("mechanism") == "SilentProcessExit" ? "MonitorProcess" : "Debugger") : item.Name;
                using var k = hive.OpenSubKey(sub, writable: true) ?? throw new InvalidOperationException("Clave no encontrada");
                var value = k.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                var kind = k.GetValueKind(valueName);
                k.DeleteValue(valueName);
                return Record("registry_value", item.Key, $"Deshabilitamos \"{item.DisplayName}\" del arranque.",
                    new RegistryBackup(item.Location, valueName, value?.ToString(), kind.ToString()));
            }
            case PersistenceType.Startup:
            {
                var file = item.Extra.GetValueOrDefault("file") ?? Path.Combine(item.Location, item.Name);
                var backup = Path.Combine(DemiurgePaths.Backups, $"{Guid.NewGuid():N}_{Path.GetFileName(file)}");
                SafeFile.MoveOut(file, backup);
                return Record("file_move", item.Key, $"Sacamos \"{item.Name}\" de la carpeta de Inicio.", new FileMoveBackup(file, backup));
            }
            case PersistenceType.Task:
            {
                using var ts = new TaskService();
                var task = ts.GetTask(item.Location) ?? throw new InvalidOperationException("Tarea no encontrada");
                task.Enabled = false;
                return Record("task_disable", item.Key, $"Deshabilitamos la tarea programada \"{item.Name}\".", new TaskBackup(item.Location));
            }
            case PersistenceType.Service:
            {
                using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{item.Name}", writable: true)
                    ?? throw new InvalidOperationException("Servicio no encontrado");
                var prev = k.GetValue("Start") is int i ? i : 3;
                k.SetValue("Start", 4, RegistryValueKind.DWord);
                return Record("service_start", item.Key, $"Deshabilitamos el servicio \"{item.Name}\" (no va a arrancar en el próximo reinicio).", new ServiceBackup(item.Name, prev));
            }
            case PersistenceType.Winlogon:
            {
                using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", writable: true)!;
                var prev = k.GetValue(item.Name)?.ToString();
                var def = item.Name switch { "Userinit" => Path.Combine(PathClassifier.System32Dir, "userinit.exe") + ",", "Shell" => "explorer.exe", _ => null };
                if (def is null) k.DeleteValue(item.Name, false); else k.SetValue(item.Name, def);
                return Record("registry_value", item.Key, $"Restauramos el valor de Windows \"{item.Name}\".",
                    new RegistryBackup(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", item.Name, prev, "String"));
            }
            case PersistenceType.OfficeAddin when item.Location.Contains("Addins", StringComparison.OrdinalIgnoreCase):
            {
                var (hive, sub) = OpenHive(item.Location + "\\" + item.Name);
                using var k = hive.OpenSubKey(sub, writable: true)!;
                var prev = k.GetValue("LoadBehavior")?.ToString();
                k.SetValue("LoadBehavior", 0, RegistryValueKind.DWord);
                return Record("registry_value", item.Key, $"Deshabilitamos el complemento de Office \"{item.Name}\".",
                    new RegistryBackup(item.Location + "\\" + item.Name, "LoadBehavior", prev, "DWord"));
            }
            case PersistenceType.ComHijack:
            {
                var (hive, sub) = OpenHive(item.Location);
                var export = ExportKey(hive, sub);
                hive.DeleteSubKeyTree(sub, false);
                return Record("registry_tree", item.Key, "Eliminamos el secuestro del componente COM.", new RegistryTreeBackup(item.Location, export));
            }
            default:
                return new ActionResult { Message = $"Este tipo de arranque ({item.Type}) se tiene que quitar a mano por ahora." };
        }
    }

    // ---------------------------------------------------------------- WMI

    private ActionResult RemoveWmi(ActionRequest req, ScanSnapshot s)
    {
        var item = PersistenceFor(req.EntityKey, s).FirstOrDefault(p => p.Type == PersistenceType.Wmi);
        if (item is null) return new ActionResult { Message = "No encontramos esa tarea WMI." };
        var scope = new ManagementScope(@"\\.\root\subscription");
        scope.Connect();
        var cls = item.Extra.GetValueOrDefault("consumerClass") ?? "CommandLineEventConsumer";
        // El nombre lo eligió quien creó la tarea: nunca se mete en el texto de una consulta. Se recorren las instancias de
        // la clase y se compara el nombre exacto acá, para borrar sólo esa tarea y nada más.
        if (!System.Text.RegularExpressions.Regex.IsMatch(cls, "^[A-Za-z_][A-Za-z0-9_]*$"))
            return new ActionResult { Message = "Tipo de tarea WMI desconocido: quitala a mano." };
        var mofParts = new List<string>();
        void DeleteMatching(string className, Func<ManagementObject, bool> match)
        {
            using var mgmtClass = new ManagementClass(scope, new ManagementPath(className), null);
            foreach (ManagementObject mo in mgmtClass.GetInstances())
            {
                using (mo)
                {
                    if (!match(mo)) continue;
                    mofParts.Add(mo.GetText(TextFormat.Mof));
                    mo.Delete();
                }
            }
        }
        static string? Prop(ManagementObject mo, string name) { try { return mo[name]?.ToString(); } catch { return null; } }
        static string? RelName(string? path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            try { var mp = new ManagementPath(path); return $"{mp.ClassName}|{mp.RelativePath}"; } catch { return null; }
        }

        bool IsTarget(ManagementObject mo) => string.Equals(Prop(mo, "Name"), item.Name, StringComparison.Ordinal);
        string? consumerRel = null;
        using (var consumers = new ManagementClass(scope, new ManagementPath(cls), null))
            foreach (ManagementObject mo in consumers.GetInstances())
                using (mo)
                    if (IsTarget(mo)) consumerRel = RelName(mo.Path.Path);
        if (consumerRel is null) return new ActionResult { Message = "No encontramos esa tarea WMI (puede que ya no exista)." };
        // Orden: vínculo, consumidor, filtro (al deshacer se recrean al revés).
        DeleteMatching("__FilterToConsumerBinding", mo => RelName(Prop(mo, "Consumer")) == consumerRel);
        DeleteMatching(cls, IsTarget);
        var filter = item.Extra.GetValueOrDefault("filter");
        if (!string.IsNullOrEmpty(filter))
            DeleteMatching("__EventFilter", mo => string.Equals(Prop(mo, "Name"), filter, StringComparison.Ordinal));
        if (mofParts.Count == 0) return new ActionResult { Message = "No encontramos esa tarea WMI (puede que ya no exista)." };
        var mofFile = Path.Combine(DemiurgePaths.Backups, $"wmi_{Guid.NewGuid():N}.mof");
        File.WriteAllText(mofFile, "#pragma namespace(\"\\\\\\\\.\\\\root\\\\subscription\")\n" + string.Join("\n", mofParts.AsEnumerable().Reverse()));
        return Record("wmi", item.Key, $"Eliminamos la tarea WMI \"{item.Name}\" (guardamos una copia).", new FileMoveBackup("", mofFile));
    }

    // ---------------------------------------------------------------- Procesos

    private ActionResult KillProcess(ActionRequest req, ScanSnapshot s)
    {
        var targets = s.Processes.Where(p => p.EndTime is null && (p.Key == req.EntityKey || p.BinaryKey == req.EntityKey)).ToList();
        var blocked = targets.FirstOrDefault(p => IsProtectedProcess(p, s));
        if (blocked is not null)
            return new ActionResult { Message = $"\"{blocked.Name}\" es una parte esencial de Windows: cerrarla apaga o cuelga la PC. No la finalizamos; si sospechás de ella, revisá la tarjeta o pedí ayuda." };
        int killed = 0;
        foreach (var p in targets)
        {
            if (TryKill(p)) killed++;
        }
        if (killed == 0) return new ActionResult { Message = "El programa ya no estaba en ejecución." };
        return Record("kill", req.EntityKey, $"Finalizamos {killed} proceso(s). Si el programa arranca solo, también conviene deshabilitar su arranque.", new { pids = targets.Select(t => t.Pid) }, reversible: false);
    }

    private ActionResult Quarantine(ActionRequest req, ScanSnapshot s)
    {
        var bin = s.GetBinary(req.EntityKey) ?? s.Binaries.Values.FirstOrDefault(b => s.Persistence.Any(p => p.Key == req.EntityKey && p.BinaryKey == b.Key));
        if (bin is null || !File.Exists(bin.Path)) return new ActionResult { Message = "No encontramos el archivo." };
        // Nada de la carpeta de Windows, nada firmado por Microsoft (esté donde esté) y nada de Demiurge: un falso
        // positivo ahí rompería Windows. Esos casos se revisan a mano.
        if (PathClassifier.IsInWindowsDir(bin.Path) || bin.Signature?.IsMicrosoft == true || IsUnder(bin.Path, AppContext.BaseDirectory))
            return new ActionResult { Message = "Es un archivo de Windows o firmado por Microsoft: no lo movemos a cuarentena porque podría dejar de funcionar la PC." };

        foreach (var p in s.Processes.Where(p => p.BinaryKey == bin.Key && p.EndTime is null))
            TryKill(p, waitMs: 5000);

        var dest = Path.Combine(DemiurgePaths.Quarantine, $"{bin.Sha256 ?? Guid.NewGuid().ToString("N")}.quarantine");
        // Ofuscamos con XOR para que no se pueda ejecutar ni dispare el AV desde la cuarentena. Se verifica que el
        // archivo sea el mismo que se escaneó (hash) y que la ruta no esté redirigida por un enlace.
        SafeFile.MoveOut(bin.Path, dest, Xor, bin.Sha256);
        return Record("quarantine", bin.Key, $"Movimos \"{bin.DisplayName}\" a cuarentena. No se borró: se puede restaurar.",
            new QuarantineBackup(bin.Path, dest, bin.Sha256));
    }

    // ---------------------------------------------------------------- Defender

    private ActionResult RemoveExclusion(ActionRequest req, ScanSnapshot s)
    {
        var setting = s.Settings.FirstOrDefault(x => x.Key == req.EntityKey && x.Name.StartsWith("defender_exclusion_"));
        if (setting?.Value is null) return new ActionResult { Message = "No encontramos esa exclusión." };
        var param = setting.Name switch
        {
            "defender_exclusion_process" => "ExclusionProcess",
            "defender_exclusion_extension" => "ExclusionExtension",
            _ => "ExclusionPath",
        };
        InvokeMpPreference("Remove", param, setting.Value);
        return Record("defender_exclusion", setting.Key, $"Quitamos la exclusión del antivirus para {setting.Value}.", new ExclusionBackup(param, setting.Value));
    }

    private static void InvokeMpPreference(string method, string param, string value)
    {
        using var cls = new ManagementClass(@"\\.\root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);
        using var inParams = cls.GetMethodParameters(method);
        inParams[param] = new[] { value };
        cls.InvokeMethod(method, inParams, null);
    }

    // ---------------------------------------------------------------- Red

    private const string DefaultHosts = """
        # Copyright (c) 1993-2009 Microsoft Corp.
        #
        # This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
        #
        # localhost name resolution is handled within DNS itself.
        #	127.0.0.1       localhost
        #	::1             localhost

        """;

    private ActionResult RestoreHosts()
    {
        var hosts = Path.Combine(PathClassifier.System32Dir, @"drivers\etc\hosts");
        var backup = Path.Combine(DemiurgePaths.Backups, $"hosts_{DateTime.Now:yyyyMMddHHmmss}");
        File.Copy(hosts, backup, overwrite: true);
        File.WriteAllText(hosts, DefaultHosts.Replace("\n", "\r\n"));
        return Record("file_copy", "hosts", "Restauramos el archivo hosts a su estado original (guardamos una copia).", new FileMoveBackup(hosts, backup));
    }

    /// <summary>Vuelve el index.js de Discord a su única línea original (guarda una copia del modificado).</summary>
    private ActionResult RepairApp(ActionRequest req, ScanSnapshot s)
    {
        var app = s.AppIntegrity.FirstOrDefault(a => a.Key == req.EntityKey && a.Status == "modified");
        if (app is null) return new ActionResult { Message = "No encontramos esa aplicación modificada." };
        var backup = Path.Combine(DemiurgePaths.Backups, $"{Guid.NewGuid():N}_index.js");
        SafeFile.CopyOut(app.Path, backup);
        SafeFile.WriteAllText(app.Path, Collectors.AppIntegrityCollector.DiscordOriginalIndex);
        return Record("file_copy", app.Key, $"Reparamos {app.App}: el archivo volvió a su estado original (guardamos una copia del modificado). Cerrá y abrí {app.App}, y cambiá tu contraseña.",
            new FileMoveBackup(app.Path, backup));
    }

    private ActionResult RestoreProxy()
    {
        var saved = new List<RegistryBackup>();
        foreach (var (_, _, root) in UserProfiles.UserHives())
        {
            using (root)
            {
                using var k = root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: true);
                if (k is null) continue;
                var name = root.Name.Replace("HKEY_USERS", "HKU").Replace("HKEY_CURRENT_USER", "HKCU");
                foreach (var v in new[] { "ProxyEnable", "ProxyServer", "AutoConfigURL" })
                {
                    var val = k.GetValue(v);
                    if (val is null) continue;
                    saved.Add(new RegistryBackup($@"{name}\Software\Microsoft\Windows\CurrentVersion\Internet Settings", v, val.ToString(), k.GetValueKind(v).ToString()));
                }
                k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                k.DeleteValue("AutoConfigURL", false);
            }
        }
        var winhttp = RunNetsh("winhttp show proxy");
        RunNetsh("winhttp reset proxy");
        return Record("proxy", "network_proxy", "Quitamos el proxy configurado (guardamos la configuración anterior).", new ProxyBackup(saved, winhttp));
    }

    private static string RunNetsh(string args)
    {
        var psi = new ProcessStartInfo(Path.Combine(PathClassifier.System32Dir, "netsh.exe"), args) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEnd();
        p.WaitForExit(10000);
        return o;
    }

    // ---------------------------------------------------------------- Navegadores

    private static void EnsureBrowserClosed(string browser)
    {
        var exe = browser switch
        {
            "Chrome" => "chrome", "Edge" => "msedge", "Brave" => "brave", "Opera" or "Opera GX" => "opera", "Vivaldi" => "vivaldi", "Firefox" => "firefox", _ => null,
        };
        if (exe is not null && Process.GetProcessesByName(exe).Length > 0)
            throw new InvalidOperationException($"Cerrá {browser} antes de continuar (si está abierto, deshace el cambio al cerrarse).");
    }

    private ActionResult RestoreBrowser(ActionRequest req, ScanSnapshot s)
    {
        var settings = s.BrowserSettings.Where(b => $"browser:{b.Browser}|{b.User}|{b.Profile}|{b.Setting}".ToLowerInvariant() == req.EntityKey || b.Key == req.EntityKey).ToList();
        if (settings.Count == 0) return new ActionResult { Message = "No encontramos esa configuración." };
        var first = settings[0];

        if (first.Setting == "policy")
        {
            // Política forzada por registro: borrar el valor (con backup).
            var name = first.Value.Split('=')[0];
            var saved = new List<RegistryBackup>();
            foreach (var hive in new[] { Registry.LocalMachine })
            {
                foreach (var policyKey in new[] { @"SOFTWARE\Policies\Google\Chrome", @"SOFTWARE\Policies\Microsoft\Edge", @"SOFTWARE\Policies\BraveSoftware\Brave" })
                {
                    using var k = hive.OpenSubKey(policyKey, writable: true);
                    var v = k?.GetValue(name);
                    if (v is null) continue;
                    saved.Add(new RegistryBackup($@"HKLM\{policyKey}", name, v.ToString(), k!.GetValueKind(name).ToString()));
                    k.DeleteValue(name);
                }
            }
            return Record("registry_values", req.EntityKey, $"Quitamos la política forzada \"{name}\" del navegador.", saved);
        }

        EnsureBrowserClosed(first.Browser);
        if (first.ProfilePath is null) return new ActionResult { Message = "No encontramos el perfil del navegador." };

        if (first.Browser == "Firefox")
        {
            var prefs = Path.Combine(first.ProfilePath, "prefs.js");
            var backup = BackupFile(prefs);
            var lines = SafeFile.ReadAllText(prefs).Split('\n').Where(l => !l.Contains("\"browser.startup.homepage\"") && !l.Contains("\"network.proxy.") && !l.Contains("\"browser.urlbar.placeholderName\"")).ToArray();
            SafeFile.WriteAllText(prefs, string.Join('\n', lines));
            return Record("file_copy", req.EntityKey, "Restauramos la página de inicio y el buscador de Firefox.", new FileMoveBackup(prefs, backup));
        }

        var file = Path.Combine(first.ProfilePath, "Preferences");
        var bak = BackupFile(file);
        var json = JsonNode.Parse(SafeFile.ReadAllText(file))!.AsObject();
        json.Remove("default_search_provider_data");
        json.Remove("homepage");
        json.Remove("homepage_is_newtabpage");
        if (json["session"] is JsonObject session)
        {
            session.Remove("startup_urls");
            session["restore_on_startup"] = 5; // página de nueva pestaña
        }
        SafeFile.WriteAllText(file, json.ToJsonString());
        return Record("file_copy", req.EntityKey, $"Restauramos el buscador y la página de inicio de {first.Browser}.", new FileMoveBackup(file, bak));
    }

    private ActionResult RemoveExtension(ActionRequest req, ScanSnapshot s)
    {
        var ext = s.Extensions.FirstOrDefault(e => e.Key == req.EntityKey);
        if (ext?.ProfilePath is null) return new ActionResult { Message = "No encontramos la extensión." };
        EnsureBrowserClosed(ext.Browser);

        if (ext.Browser == "Firefox")
        {
            var xpi = Path.Combine(ext.ProfilePath, "extensions", ext.Id + ".xpi");
            if (!File.Exists(xpi)) return new ActionResult { Message = "No encontramos el archivo de la extensión; quitala desde el menú de complementos." };
            var dest = Path.Combine(DemiurgePaths.Backups, $"{Guid.NewGuid():N}_{ext.Id}.xpi");
            SafeFile.MoveOut(xpi, dest);
            return Record("file_move", ext.Key, $"Quitamos la extensión \"{ext.Name}\" de Firefox.", new FileMoveBackup(xpi, dest));
        }

        var dir = Path.Combine(ext.ProfilePath, "Extensions", ext.Id);
        var moved = new List<FileMoveBackup>();
        if (Directory.Exists(dir))
        {
            var dest = Path.Combine(DemiurgePaths.Backups, $"{Guid.NewGuid():N}_{ext.Id}");
            SafeFile.VerifyDirectory(dir); // falla si la carpeta es un junction a otro lado
            Directory.Move(dir, dest);
            moved.Add(new FileMoveBackup(dir, dest));
        }
        foreach (var prefName in new[] { "Secure Preferences", "Preferences" })
        {
            var file = Path.Combine(ext.ProfilePath, prefName);
            if (!File.Exists(file)) continue;
            var json = JsonNode.Parse(SafeFile.ReadAllText(file))?.AsObject();
            if (json?["extensions"]?["settings"] is JsonObject settings && settings.ContainsKey(ext.Id))
            {
                moved.Add(new FileMoveBackup(file, BackupFile(file)));
                settings.Remove(ext.Id);
                SafeFile.WriteAllText(file, json.ToJsonString());
            }
        }
        return Record("multi_file", ext.Key, $"Quitamos la extensión \"{ext.Name}\" de {ext.Browser}.", moved);
    }

    private ActionResult RemoveNotifications(ActionRequest req, ScanSnapshot s)
    {
        var key = req.EntityKey;
        var targets = s.BrowserSettings.Where(b => b.Setting == "notifications" &&
            $"notifications:{b.Browser}|{b.User}|{b.Profile}".ToLowerInvariant() == key).ToList();
        if (targets.Count == 0 || targets[0].ProfilePath is null) return new ActionResult { Message = "No encontramos los permisos." };
        var first = targets[0];
        EnsureBrowserClosed(first.Browser);

        if (first.Browser == "Firefox")
        {
            var db = Path.Combine(first.ProfilePath!, "permissions.sqlite");
            var bak = BackupFile(db);
            // Se edita una copia en nuestra carpeta protegida y se escribe de vuelta por el handle verificado.
            var work = Path.Combine(DemiurgePaths.Backups, $"{Guid.NewGuid():N}_work.sqlite");
            File.Copy(bak, work);
            using (var conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={work};Pooling=False"))
            {
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM moz_perms WHERE type = 'desktop-notification'";
                cmd.ExecuteNonQuery();
            }
            SafeFile.WriteAllBytes(db, File.ReadAllBytes(work));
            File.Delete(work);
            return Record("file_copy", key, "Quitamos los permisos de notificación de Firefox.", new FileMoveBackup(db, bak));
        }

        var file = Path.Combine(first.ProfilePath!, "Preferences");
        var backup = BackupFile(file);
        var json = JsonNode.Parse(SafeFile.ReadAllText(file))!.AsObject();
        if (json["profile"]?["content_settings"]?["exceptions"]?["notifications"] is JsonObject notif)
            foreach (var t in targets)
                foreach (var k in notif.Select(kv => kv.Key).Where(k => k.StartsWith(t.Value, StringComparison.OrdinalIgnoreCase)).ToList())
                    notif.Remove(k);
        SafeFile.WriteAllText(file, json.ToJsonString());
        return Record("file_copy", key, $"Quitamos {targets.Count} permiso(s) de notificación de {first.Browser}.", new FileMoveBackup(file, backup));
    }

    // ---------------------------------------------------------------- Cuentas y certificados

    private ActionResult DisableAccount(ActionRequest req, ScanSnapshot s)
    {
        var acc = s.Accounts.FirstOrDefault(a => a.Key == req.EntityKey);
        if (acc is null) return new ActionResult { Message = "No encontramos la cuenta." };
        using var pc = new PrincipalContext(ContextType.Machine);
        using var u = UserPrincipal.FindByIdentity(pc, IdentityType.SamAccountName, acc.Name) ?? throw new InvalidOperationException("Cuenta no encontrada");
        u.Enabled = false;
        u.Save();
        return Record("account", acc.Key, $"Deshabilitamos la cuenta \"{acc.Name}\" (no se borró).", new AccountBackup(acc.Name));
    }

    private ActionResult RemoveCertificate(ActionRequest req, ScanSnapshot s)
    {
        var thumb = req.EntityKey.StartsWith("cert:") ? req.EntityKey[5..] : null;
        var certs = s.Certificates.Where(c => c.Key == req.EntityKey || (thumb is not null && c.Thumbprint.Equals(thumb, StringComparison.OrdinalIgnoreCase))).ToList();
        if (certs.Count == 0) return new ActionResult { Message = "No encontramos el certificado." };
        var backups = new List<CertBackup>();
        foreach (var c in certs)
        {
            var loc = c.Store.StartsWith("LocalMachine") ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
            using var store = new X509Store(StoreName.Root, loc);
            store.Open(OpenFlags.ReadWrite);
            foreach (var x in store.Certificates.Find(X509FindType.FindByThumbprint, c.Thumbprint, false))
            {
                var file = Path.Combine(DemiurgePaths.Backups, $"{c.Thumbprint}.cer");
                File.WriteAllBytes(file, x.Export(X509ContentType.Cert));
                store.Remove(x);
                backups.Add(new CertBackup(loc.ToString(), file));
            }
        }
        if (backups.Count == 0) return new ActionResult { Message = "El certificado está en el perfil de otro usuario; quitalo desde esa sesión (certmgr.msc)." };
        return Record("certificate", req.EntityKey, $"Quitamos el certificado \"{certs[0].Subject}\" (guardamos una copia).", backups);
    }

    private ActionResult Allowlist(ActionRequest req, ScanSnapshot s)
    {
        var name = s.Scores.FirstOrDefault(x => x.ScoringKey == req.EntityKey)?.DisplayName
                   ?? s.AllEntities().FirstOrDefault(e => e.Key == req.EntityKey)?.DisplayName;
        _db.AddAllowlist(new AllowlistEntry { EntityKey = req.EntityKey, DisplayName = name, Note = req.Note, Date = DateTimeOffset.Now });
        return Record("allowlist", req.EntityKey, $"Listo: marcamos \"{name ?? req.EntityKey}\" como reconocido. Podés revertirlo cuando quieras.", new { key = req.EntityKey });
    }

    // ---------------------------------------------------------------- Revertir

    public ActionResult Revert(string actionId)
    {
        var rec = _db.GetActions(1000).FirstOrDefault(a => a.Id == actionId);
        if (rec is null) return new ActionResult { Message = "No encontramos esa acción." };
        if (rec.Reverted) return new ActionResult { Message = "Esa acción ya fue revertida." };
        try
        {
            switch (rec.Type)
            {
                case "registry_value":
                    RestoreRegistry(Deserialize<RegistryBackup>(rec.Backup));
                    break;
                case "registry_values":
                    foreach (var b in Deserialize<List<RegistryBackup>>(rec.Backup)) RestoreRegistry(b);
                    break;
                case "registry_tree":
                {
                    var b = Deserialize<RegistryTreeBackup>(rec.Backup);
                    var (hive, sub) = OpenHive(b.Location);
                    ImportKey(hive, sub, b.Values);
                    break;
                }
                case "file_move":
                {
                    var b = Deserialize<FileMoveBackup>(rec.Backup);
                    if (Directory.Exists(b.Backup))
                    {
                        SafeFile.RestoreDirectory(b.Backup, b.Original);
                    }
                    else
                    {
                        SafeFile.RestoreTo(b.Backup, b.Original);
                        File.Delete(b.Backup);
                    }
                    break;
                }
                case "file_copy":
                {
                    var b = Deserialize<FileMoveBackup>(rec.Backup);
                    if (b.Original.StartsWith(PathClassifier.WindowsDir, StringComparison.OrdinalIgnoreCase))
                        File.Copy(b.Backup, b.Original, overwrite: true); // hosts: carpeta sólo de administradores
                    else
                        SafeFile.RestoreTo(b.Backup, b.Original);
                    break;
                }
                case "multi_file":
                    foreach (var b in Deserialize<List<FileMoveBackup>>(rec.Backup))
                    {
                        if (Directory.Exists(b.Backup))
                        {
                            SafeFile.RestoreDirectory(b.Backup, b.Original);
                        }
                        else SafeFile.RestoreTo(b.Backup, b.Original);
                    }
                    break;
                case "task_disable":
                {
                    using var ts = new TaskService();
                    var t = ts.GetTask(Deserialize<TaskBackup>(rec.Backup).Path);
                    if (t is not null) t.Enabled = true;
                    break;
                }
                case "service_start":
                {
                    var b = Deserialize<ServiceBackup>(rec.Backup);
                    using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{b.Name}", writable: true)!;
                    k.SetValue("Start", b.PreviousStart, RegistryValueKind.DWord);
                    break;
                }
                case "wmi":
                {
                    var b = Deserialize<FileMoveBackup>(rec.Backup);
                    var mofcomp = Path.Combine(PathClassifier.System32Dir, "wbem", "mofcomp.exe");
                    using var p = Process.Start(new ProcessStartInfo(mofcomp, $"\"{b.Backup}\"") { UseShellExecute = false, CreateNoWindow = true })!;
                    p.WaitForExit(30000);
                    break;
                }
                case "quarantine":
                {
                    var b = Deserialize<QuarantineBackup>(rec.Backup);
                    var restored = Path.Combine(DemiurgePaths.Quarantine, $"{Guid.NewGuid():N}.restore");
                    File.WriteAllBytes(restored, Xor(File.ReadAllBytes(b.QuarantinePath)));
                    SafeFile.RestoreTo(restored, b.OriginalPath);
                    File.Delete(restored);
                    File.Delete(b.QuarantinePath);
                    break;
                }
                case "defender_exclusion":
                {
                    var b = Deserialize<ExclusionBackup>(rec.Backup);
                    InvokeMpPreference("Add", b.Parameter, b.Value);
                    break;
                }
                case "proxy":
                {
                    var b = Deserialize<ProxyBackup>(rec.Backup);
                    foreach (var r in b.WinInet) RestoreRegistry(r);
                    var server = b.WinHttp.Split('\n').FirstOrDefault(l => l.Contains("Proxy Server", StringComparison.OrdinalIgnoreCase))?.Split(':', 2).ElementAtOrDefault(1)?.Trim();
                    if (!string.IsNullOrEmpty(server)) RunNetsh($"winhttp set proxy {server}");
                    break;
                }
                case "account":
                {
                    using var pc = new PrincipalContext(ContextType.Machine);
                    using var u = UserPrincipal.FindByIdentity(pc, IdentityType.SamAccountName, Deserialize<AccountBackup>(rec.Backup).Name)!;
                    u.Enabled = true;
                    u.Save();
                    break;
                }
                case "certificate":
                    foreach (var b in Deserialize<List<CertBackup>>(rec.Backup))
                    {
                        using var store = new X509Store(StoreName.Root, Enum.Parse<StoreLocation>(b.Location));
                        store.Open(OpenFlags.ReadWrite);
                        store.Add(X509CertificateLoader.LoadCertificateFromFile(b.File));
                    }
                    break;
                case "allowlist":
                    _db.RemoveAllowlist(rec.Target);
                    break;
                default:
                    return new ActionResult { Message = "Esta acción no se puede revertir (por ejemplo, finalizar un proceso)." };
            }
            rec.Reverted = true;
            _db.SaveAction(rec);
            return new ActionResult { Success = true, Message = $"Revertimos: {rec.Description}" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "No se pudo revertir {Id}", actionId);
            return new ActionResult { Message = "No se pudo revertir: " + ex.Message };
        }
    }

    // ---------------------------------------------------------------- helpers

    /// <summary>Procesos que no se finalizan nunca: el kernel, los críticos de Windows (cerrarlos es pantalla azul) y Demiurge.</summary>
    private static readonly HashSet<string> CriticalProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Registry", "Idle", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
        "lsaiso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "MsMpEng.exe", "NisSrv.exe", "MemCompression", "explorer.exe",
    };

    internal static bool IsProtectedProcess(ProcessInfo p, ScanSnapshot s)
    {
        if (p.Pid is 0 or 4 || p.Pid == Environment.ProcessId) return true;
        var path = p.Path;
        // Un "svchost.exe" en AppData es justamente lo sospechoso: el nombre protege sólo si está en la carpeta de Windows.
        if (CriticalProcessNames.Contains(p.Name) && (path is null || PathClassifier.IsInWindowsDir(path))) return true;
        return path is not null && PathClassifier.IsInWindowsDir(path) && s.GetBinary(p.BinaryKey)?.Signature?.IsMicrosoft == true;
    }

    /// <summary>Finaliza un proceso sólo si sigue siendo el mismo que se escaneó (el PID se reutiliza).</summary>
    private static bool TryKill(ProcessInfo p, int waitMs = 0)
    {
        try
        {
            using var proc = Process.GetProcessById(p.Pid);
            if (p.StartTime is null || Math.Abs((proc.StartTime - p.StartTime.Value.LocalDateTime).TotalSeconds) > 2) return false;
            proc.Kill(entireProcessTree: false);
            if (waitMs > 0) proc.WaitForExit(waitMs);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false; // ya terminó o no se puede abrir
        }
    }

    private static bool IsUnder(string path, string dir)
    {
        try
        {
            var full = Path.GetFullPath(path);
            var baseDir = Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return full.StartsWith(baseDir, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static byte[] Xor(byte[] data)
    {
        var copy = (byte[])data.Clone();
        for (int i = 0; i < copy.Length; i++) copy[i] ^= 0xA5;
        return copy;
    }

    private static T Deserialize<T>(string? json) => JsonSerializer.Deserialize<T>(json ?? "null", DemiurgeDb.Json)!;

    private static string BackupFile(string file)
    {
        var dest = Path.Combine(DemiurgePaths.Backups, $"{Guid.NewGuid():N}_{Path.GetFileName(file)}");
        SafeFile.CopyOut(file, dest);
        return dest;
    }

    internal static (RegistryKey hive, string sub) OpenHive(string location)
    {
        var idx = location.IndexOf('\\');
        var hiveName = location[..idx];
        var rest = location[(idx + 1)..];
        if (hiveName == "HKLM") return (Registry.LocalMachine, rest);
        if (hiveName == "HKCU") return (Registry.CurrentUser, rest);
        if (hiveName == "HKU")
        {
            // HKU\<usuario o SID>\...: resolver nombre de usuario a SID.
            var idx2 = rest.IndexOf('\\');
            var who = rest[..idx2];
            var sub = rest[(idx2 + 1)..];
            var sid = who.StartsWith("S-1-") ? who : UserProfiles.All().FirstOrDefault(p => p.UserName.Equals(who, StringComparison.OrdinalIgnoreCase))?.Sid ?? who;
            return (Registry.Users, $@"{sid}\{sub}");
        }
        throw new ArgumentException("Hive desconocido: " + hiveName);
    }

    private static void RestoreRegistry(RegistryBackup b)
    {
        var (hive, sub) = OpenHive(b.Location);
        using var k = hive.CreateSubKey(sub, writable: true);
        if (b.Value is null) { k.DeleteValue(b.Name, false); return; }
        var kind = Enum.TryParse<RegistryValueKind>(b.Kind, out var rk) ? rk : RegistryValueKind.String;
        object value = kind switch
        {
            RegistryValueKind.DWord => int.Parse(b.Value),
            RegistryValueKind.QWord => long.Parse(b.Value),
            RegistryValueKind.MultiString => b.Value.Split('\n'),
            _ => b.Value,
        };
        k.SetValue(b.Name, value, kind);
    }

    private static Dictionary<string, Dictionary<string, string>> ExportKey(RegistryKey hive, string sub)
    {
        var result = new Dictionary<string, Dictionary<string, string>>();
        void Walk(string path)
        {
            using var k = hive.OpenSubKey(path);
            if (k is null) return;
            result[path] = k.GetValueNames().ToDictionary(n => n, n => k.GetValue(n)?.ToString() ?? "");
            foreach (var child in k.GetSubKeyNames()) Walk(path + "\\" + child);
        }
        Walk(sub);
        return result;
    }

    private static void ImportKey(RegistryKey hive, string _, Dictionary<string, Dictionary<string, string>> values)
    {
        foreach (var (path, vals) in values)
        {
            using var k = hive.CreateSubKey(path, writable: true);
            foreach (var (n, v) in vals) k.SetValue(n, v);
        }
    }

    private sealed record RegistryBackup(string Location, string Name, string? Value, string Kind);
    private sealed record RegistryTreeBackup(string Location, Dictionary<string, Dictionary<string, string>> Values);
    private sealed record FileMoveBackup(string Original, string Backup);
    private sealed record TaskBackup(string Path);
    private sealed record ServiceBackup(string Name, int PreviousStart);
    private sealed record QuarantineBackup(string OriginalPath, string QuarantinePath, string? Sha256);
    private sealed record ExclusionBackup(string Parameter, string Value);
    private sealed record ProxyBackup(List<RegistryBackup> WinInet, string WinHttp);
    private sealed record AccountBackup(string Name);
    private sealed record CertBackup(string Location, string File);
}
