using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Text;

namespace Demiurge.Core.Inventory;

public sealed class InventoryRow
{
    public string Key { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Detail { get; set; }
    public string? Path { get; set; }
    public string WhatIsIt { get; set; } = "";
    public string IsItNormal { get; set; } = "";
    /// <summary>ok | info | review | danger | question</summary>
    public string Status { get; set; } = "ok";
    public int Score { get; set; }
    public string? Signer { get; set; }
    public Dictionary<string, string?> Columns { get; set; } = new();
}

/// <summary>
/// Capa 3 (08_UX_Explicaciones): inventario navegable por pestañas, cada fila con "¿Qué es esto?" y
/// "¿Es normal?" desde la KnowledgeBase. También explica lo normal que parece raro.
/// </summary>
public sealed class InventoryBuilder
{
    public static readonly string[] Tabs = ["startup", "processes", "connections", "extensions", "software", "accounts", "settings", "certificates", "drivers", "files", "history", "logons", "firewall"];

    private readonly KnowledgeBase _kb;
    private readonly TextCatalog _text;

    public InventoryBuilder(KnowledgeBase kb, TextCatalog text)
    {
        _kb = kb;
        _text = text;
    }

    public List<InventoryRow> Build(ScanSnapshot s, string tab, string? search = null)
    {
        var scoreByKey = s.Scores.ToDictionary(x => x.ScoringKey, x => x);
        var entityScore = new Dictionary<string, int>();
        foreach (var f in s.Findings.Where(f => f.Weight > 0))
        {
            entityScore[f.EntityKey] = entityScore.GetValueOrDefault(f.EntityKey) + f.Weight;
        }

        IEnumerable<InventoryRow> rows = tab switch
        {
            "startup" => s.Persistence.Select(p => Row(s, p, p.BinaryKey, p.DisplayName, $"{TypeLabel(p.Type)} · {p.Location}", p.ResolvedPath, scoreByKey, entityScore,
                cols: new() { ["tipo"] = TypeLabel(p.Type), ["comando"] = p.Command, ["habilitado"] = p.Enabled ? "sí" : "no", ["oculta"] = p.Hidden ? "sí" : null },
                kbOverride: p.Type == PersistenceType.Task ? _kb.MatchTask(p.Location) : p.Type == PersistenceType.Service ? _kb.MatchService(p.Name) : null)),
            "processes" => s.Processes.Where(p => p.EndTime is null).OrderByDescending(p => p.CpuPercent).Select(p => Row(s, p, p.BinaryKey, p.Name, $"PID {p.Pid} · {p.User}", p.Path, scoreByKey, entityScore,
                cols: new() { ["pid"] = p.Pid.ToString(), ["cpu"] = $"{p.CpuPercent:0.#}%", ["ram"] = $"{p.WorkingSetBytes / 1048576} MB", ["gpu"] = p.GpuPercent is null ? null : $"{p.GpuPercent:0.#}%", ["usuario"] = p.User, ["integridad"] = p.Integrity, ["cmdline"] = p.CommandLine })),
            "connections" => s.Connections.OrderBy(c => c.IsListening).Select(c =>
            {
                var proc = s.Processes.FirstOrDefault(p => p.Pid == c.Pid && p.EndTime is null);
                var r = Row(s, c, proc?.BinaryKey, c.ProcessName ?? $"PID {c.Pid}", c.IsListening ? $"Escuchando en puerto {c.LocalPort} ({c.Protocol})" : $"{c.Protocol} → {c.RemoteAddress}:{c.RemotePort} ({c.State})", c.ProcessPath, scoreByKey, entityScore,
                    cols: new() { ["local"] = $"{c.LocalAddress}:{c.LocalPort}", ["remoto"] = c.RemoteAddress is null ? null : $"{c.RemoteAddress}:{c.RemotePort}", ["estado"] = c.State, ["enviado"] = c.BytesOut > 0 ? $"{c.BytesOut / 1024} KB" : null, ["recibido"] = c.BytesIn > 0 ? $"{c.BytesIn / 1024} KB" : null, ["feed"] = c.TiMatch });
                return r;
            }),
            "extensions" => s.Extensions.Select(e =>
            {
                var kb = _kb.MatchExtension(e.Id);
                return new InventoryRow
                {
                    Key = e.Key, Name = e.Name, Detail = $"{e.Browser} · {e.Profile} · {OriginLabel(e.Origin)}",
                    WhatIsIt = kb?.What ?? _text["subject.Extension"] + (e.Permissions.Count > 0 ? $" con {e.Permissions.Count} permiso(s)." : "."),
                    IsItNormal = kb?.Normal ?? (e.Origin == "store" ? "Se instaló desde la tienda oficial." : "No se instaló desde la tienda oficial: si no la reconocés, quitala."),
                    Status = StatusFor(entityScore.GetValueOrDefault(e.Key), kb),
                    Score = entityScore.GetValueOrDefault(e.Key),
                    Columns = new() { ["id"] = e.Id, ["versión"] = e.Version, ["habilitada"] = e.Enabled ? "sí" : "no", ["permisos"] = string.Join(", ", e.Permissions.Take(8)) },
                };
            }),
            "software" => s.Software.OrderBy(x => x.Name).Select(sw =>
            {
                var kb = _kb.ById(sw.KbId) ?? _kb.MatchSoftware(sw);
                var score = entityScore.GetValueOrDefault(sw.Key);
                return new InventoryRow
                {
                    Key = sw.Key, Name = sw.Name, Detail = $"{sw.Publisher} {sw.Version}".Trim(),
                    WhatIsIt = kb?.What ?? (sw.Publisher is null ? "Programa instalado." : $"Programa de {sw.Publisher}."),
                    IsItNormal = kb?.Normal ?? "Si lo instalaste vos, está bien.",
                    Status = kb?.Risk == "question" ? "question" : StatusFor(score, kb),
                    Score = score,
                    Columns = new() { ["instalado"] = sw.InstallDate?.ToString("dd/MM/yyyy"), ["ubicación"] = sw.InstallLocation, ["categoría"] = sw.Category },
                };
            }),
            "accounts" => s.Accounts.Select(a => new InventoryRow
            {
                Key = a.Key, Name = a.Name, Detail = (a.IsAdmin ? "Administrador" : "Usuario estándar") + (a.Enabled ? "" : " · deshabilitada"),
                WhatIsIt = a.BuiltIn ? "Cuenta que Windows crea de fábrica." : "Cuenta de usuario local.",
                IsItNormal = a.BuiltIn ? "Sí; suele estar deshabilitada." : a.IsAdmin ? "Normal si es tu cuenta o la de alguien de confianza." : "Sí.",
                Status = StatusFor(entityScore.GetValueOrDefault(a.Key), null),
                Score = entityScore.GetValueOrDefault(a.Key),
                Columns = new() { ["creada"] = a.Created?.ToString("dd/MM/yyyy"), ["último inicio"] = a.LastLogon?.ToString("dd/MM/yyyy HH:mm"), ["grupos"] = string.Join(", ", a.Groups) },
            }),
            "settings" => s.Settings.Select(x => new InventoryRow
            {
                Key = x.Key, Name = SettingLabel(x.Name), Detail = x.Value,
                WhatIsIt = x.Detail ?? SettingLabel(x.Name),
                IsItNormal = x.Ok switch { true => "Está como se recomienda.", false => _text.Get($"health.{x.Name}", ("value", x.Value)), _ => x.Category == "infection" ? "Revisá si lo configuraste vos." : "No se pudo determinar." },
                Status = entityScore.GetValueOrDefault(x.Key) > 0 ? StatusFor(entityScore[x.Key], null) : x.Ok == false ? "review" : "ok",
                Score = entityScore.GetValueOrDefault(x.Key),
                Columns = new() { ["esperado"] = x.Expected, ["origen"] = x.Source, ["categoría"] = x.Category == "health" ? "salud" : "red/antivirus" },
            }),
            "certificates" => s.Certificates.Select(c =>
            {
                var kb = _kb.MatchCertificate(c.Subject);
                var score = s.Findings.Where(f => f.EntityKey == c.Key && f.Weight > 0).Sum(f => f.Weight);
                return new InventoryRow
                {
                    Key = c.Key, Name = c.Subject, Detail = c.Store,
                    WhatIsIt = kb?.What ?? "Certificado raíz: una 'llave maestra' que tu PC usa para confiar en sitios seguros.",
                    IsItNormal = c.InAuthRoot == true ? "Sí: está en la lista oficial de Microsoft." : kb?.Normal ?? "No está en la lista oficial de Microsoft: revisá si lo instalaste vos.",
                    Status = c.InAuthRoot == true ? "ok" : StatusFor(score, kb),
                    Score = score,
                    Columns = new() { ["emisor"] = c.Issuer, ["huella"] = c.Thumbprint, ["vence"] = c.NotAfter.ToString("dd/MM/yyyy") },
                };
            }),
            "drivers" => s.Drivers.Where(d => d.State == "Running").Select(d => Row(s, d, d.BinaryKey, d.DisplayName, d.Name, d.Path, scoreByKey, entityScore,
                cols: new() { ["estado"] = d.State, ["inicio"] = d.StartMode })),
            "files" => s.RecentFiles.OrderByDescending(f => f.Modified).Select(f => Row(s, f, f.BinaryKey, f.DisplayName, f.Modified.ToString("dd/MM/yyyy HH:mm"), f.Path, scoreByKey, entityScore,
                cols: new() { ["descargado de"] = f.HostUrl, ["zona"] = f.ZoneId?.ToString(), ["doble extensión"] = f.DoubleExtension ? "sí" : null, ["tamaño"] = $"{f.Size / 1024} KB" })),
            "history" => History(s, scoreByKey, entityScore),
            "logons" => Logons(s, entityScore),
            "firewall" => Firewall(s, scoreByKey, entityScore),
            _ => [],
        };

        if (!string.IsNullOrWhiteSpace(search))
            rows = rows.Where(r => r.Name.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                                   (r.Detail?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                   (r.Path?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false));
        return rows.OrderByDescending(r => r.Score).ToList();
    }

    private InventoryRow Row(ScanSnapshot s, IEntity e, string? binaryKey, string name, string? detail, string? path,
        Dictionary<string, EntityScore> scores, Dictionary<string, int> entityScore, Dictionary<string, string?> cols, KnowledgeEntry? kbOverride = null)
    {
        var bin = s.GetBinary(binaryKey);
        var match = _kb.MatchBinary(bin);
        var kb = kbOverride ?? match?.Entry;
        int score = Math.Max(entityScore.GetValueOrDefault(e.Key), binaryKey is not null && scores.TryGetValue(binaryKey, out var sc) ? sc.Score : 0);

        string what = kb?.What ?? bin?.FileDescription ?? _text["unknown.what"];
        string normal;
        if (match is { Mismatch: true } && kbOverride is null)
            normal = "Tiene el nombre de un programa conocido pero no la firma o ubicación esperadas: revisalo.";
        else if (kb is not null)
            normal = kb.Normal;
        else if (bin?.Signature?.IsValid == true)
            normal = _text.Get("unknown.normal.signed", ("signer", bin.Signature.Signer));
        else
            normal = _text["unknown.normal.unsigned"];

        return new InventoryRow
        {
            Key = e.Key,
            Name = name,
            Detail = detail,
            Path = path,
            WhatIsIt = what,
            IsItNormal = normal,
            Status = StatusFor(score, kb),
            Score = score,
            Signer = bin?.Signature?.IsValid == true ? bin.Signature.Signer : bin?.Signature?.IsSigned == true ? "firma inválida" : bin is null ? null : "sin firma",
            Columns = cols,
        };
    }

    /// <summary>Historial de ejecución: lo más reciente primero; lo que ya no existe y estaba en carpetas de usuario, resaltado.</summary>
    private IEnumerable<InventoryRow> History(ScanSnapshot s, Dictionary<string, EntityScore> scores, Dictionary<string, int> entityScore) =>
        s.Executions.OrderByDescending(x => x.LastRun ?? DateTimeOffset.MinValue).Take(1500).Select(x =>
        {
            var when = x.LastRun is null ? "fecha desconocida" : x.LastRun.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm");
            var detail = $"Última vez: {when}" + (x.RunCount is > 0 ? $" · {x.RunCount} vez/veces" : "") + $" · {string.Join(", ", x.Sources)}";
            if (x.BinaryKey is not null && x.Exists == true)
            {
                var row = Row(s, x, x.BinaryKey, x.Name, detail, x.Path, scores, entityScore, new() { ["usuario"] = x.User });
                row.WhatIsIt = $"Se ejecutó en esta PC. {row.WhatIsIt}";
                return row;
            }
            var gone = x.Exists == false;
            var userFolder = Util.PathClassifier.UserWritableFolder(x.Path);
            var score = entityScore.GetValueOrDefault(x.Key);
            return new InventoryRow
            {
                Key = x.Key, Name = x.Name, Detail = detail, Path = x.Path,
                WhatIsIt = x.Path is null ? "Se ejecutó en esta PC (Windows sólo guardó el nombre)." : "Se ejecutó en esta PC.",
                IsItNormal = gone && userFolder is not null ? $"Ya no está en el disco y corría desde {userFolder}: si no recordás haberlo ejecutado, revisalo."
                    : gone ? "Ya no está en el disco (lo desinstalaste o se actualizó)."
                    : Util.PathClassifier.IsInWindowsDir(x.Path) ? "Es parte de Windows." : "Normal si lo usás.",
                Status = score > 0 ? StatusFor(score, null) : gone && userFolder is not null ? "info" : "ok",
                Score = score,
                Columns = new() { ["usuario"] = x.User },
            };
        });

    /// <summary>Inicios de sesión por Escritorio remoto e intentos fallidos, agrupados.</summary>
    private IEnumerable<InventoryRow> Logons(ScanSnapshot s, Dictionary<string, int> entityScore)
    {
        var rows = new List<InventoryRow>();
        foreach (var g in s.Events.Where(e => e.EventId == 4624).GroupBy(e => (u: e.Data.GetValueOrDefault("TargetUserName") ?? "?", ip: e.Data.GetValueOrDefault("IpAddress") ?? "-")))
        {
            var key = $"logon:rdp:{g.Key.u}|{g.Key.ip}".ToLowerInvariant();
            var last = g.Max(e => e.Timestamp).ToLocalTime();
            rows.Add(new InventoryRow
            {
                Key = key, Name = $"Escritorio remoto: {g.Key.u}", Detail = $"Desde {g.Key.ip} · {g.Count()} vez/veces · última {last:dd/MM/yyyy HH:mm}",
                WhatIsIt = "Alguien inició sesión en esta PC a distancia.",
                IsItNormal = "Normal sólo si fuiste vos o alguien de confianza.",
                Status = "question", Score = 0,
                Columns = new(),
            });
        }
        foreach (var g in s.Events.Where(e => e.EventId == 4625).GroupBy(e => e.Data.GetValueOrDefault("IpAddress") is { Length: > 1 } ip && ip != "127.0.0.1" ? ip : "esta PC"))
        {
            var accounts = string.Join(", ", g.Select(e => e.Data.GetValueOrDefault("TargetUserName")).Where(a => !string.IsNullOrEmpty(a)).Distinct().Take(4));
            var key = $"logon:failures:{(g.Key == "esta PC" ? "local" : g.Key)}".ToLowerInvariant();
            var score = entityScore.GetValueOrDefault(key);
            rows.Add(new InventoryRow
            {
                Key = key, Name = $"Contraseña incorrecta: {g.Key}", Detail = $"{g.Count()} intento(s) fallido(s) · cuentas: {accounts}",
                WhatIsIt = "Intentos de iniciar sesión con una contraseña equivocada.",
                IsItNormal = g.Count() < 10 ? "Unos pocos son normales (un PIN mal tipeado)." : "Muchos intentos seguidos pueden ser alguien tratando de adivinar la contraseña.",
                Status = score > 0 ? StatusFor(score, null) : g.Count() >= 10 ? "info" : "ok",
                Score = score,
                Columns = new(),
            });
        }
        if (rows.Count == 0)
            rows.Add(new InventoryRow { Key = "logons-none", Name = "Sin accesos remotos ni contraseñas fallidas", WhatIsIt = "En los últimos días no hubo inicios de sesión por Escritorio remoto ni intentos fallidos registrados.", IsItNormal = "Sí. (Requiere permisos de administrador para leer el registro de seguridad.)", Status = "ok", Columns = new() });
        return rows;
    }

    /// <summary>Reglas del firewall que no son de Windows; primero las que permiten conexiones entrantes.</summary>
    private IEnumerable<InventoryRow> Firewall(ScanSnapshot s, Dictionary<string, EntityScore> scores, Dictionary<string, int> entityScore) =>
        s.FirewallRules.Where(r => !r.BuiltIn)
            .OrderByDescending(r => r.Active && r.Action == "Allow" && r.Direction == "In")
            .ThenBy(r => r.Name)
            .Select(r =>
            {
                var what = $"{(r.Action == "Allow" ? "Permite" : "Bloquea")} conexiones {(r.Direction == "In" ? "entrantes" : "salientes")}" +
                           (r.LocalPorts is null ? "" : $" · puertos {r.LocalPorts}") + (r.Active ? "" : " · desactivada") + (r.Store == "policy" ? " · por política" : "");
                if (r.BinaryKey is not null)
                {
                    var row = Row(s, r, r.BinaryKey, r.Name, what, r.App, scores, entityScore, new() { ["protocolo"] = r.Protocol, ["perfiles"] = r.Profiles });
                    row.WhatIsIt = $"Regla del firewall para este programa. {row.WhatIsIt}";
                    return row;
                }
                var score = entityScore.GetValueOrDefault(r.Key);
                return new InventoryRow
                {
                    Key = r.Key, Name = r.Name, Detail = what, Path = r.App ?? r.Service,
                    WhatIsIt = "Regla del firewall creada por un programa o por vos.",
                    IsItNormal = r.Action == "Allow" && r.Direction == "In" && r.Active ? "Abre la PC a conexiones desde afuera: normal si es de un programa que usás (juegos, herramientas de red)." : "Sí.",
                    Status = score > 0 ? StatusFor(score, null) : "ok",
                    Score = score,
                    Columns = new() { ["protocolo"] = r.Protocol, ["perfiles"] = r.Profiles },
                };
            });

    private static string StatusFor(int score, KnowledgeEntry? kb) =>
        score >= 60 ? "danger" : score >= 20 ? "review" : kb?.Risk == "question" ? "question" : kb?.Risk is "pup" or "suspicious" ? "review" : score > 0 ? "info" : "ok";

    private static string TypeLabel(PersistenceType t) => t switch
    {
        PersistenceType.RunKey => "Registro (Run)",
        PersistenceType.RunOnce => "Registro (RunOnce)",
        PersistenceType.Startup => "Carpeta Inicio",
        PersistenceType.Task => "Tarea programada",
        PersistenceType.Service => "Servicio",
        PersistenceType.Wmi => "WMI",
        PersistenceType.Ifeo => "IFEO (reemplazo de programa)",
        PersistenceType.Winlogon => "Inicio de sesión",
        PersistenceType.AppInit => "AppInit_DLLs",
        PersistenceType.Bits => "Descarga BITS",
        PersistenceType.Lsa => "Paquete de seguridad LSA",
        PersistenceType.ComHijack => "Componente COM",
        PersistenceType.OfficeAddin => "Complemento de Office",
        _ => t.ToString(),
    };

    private static string OriginLabel(string origin) => origin switch
    {
        "store" => "tienda oficial",
        "sideload" => "instalada por fuera de la tienda",
        "policy" => "forzada por política",
        _ => "origen desconocido",
    };

    internal static string SettingLabel(string name) => name switch
    {
        "defender_rtp" => "Protección en tiempo real",
        "defender_signatures" => "Antigüedad de definiciones del antivirus (días)",
        "other_av" => "Otros antivirus",
        "defender_exclusion_path" => "Exclusión del antivirus (carpeta)",
        "defender_exclusion_process" => "Exclusión del antivirus (programa)",
        "defender_exclusion_extension" => "Exclusión del antivirus (extensión)",
        "firewall_domain" => "Firewall (dominio)",
        "firewall_private" => "Firewall (red privada)",
        "firewall_public" => "Firewall (red pública)",
        "uac" => "Control de cuentas de usuario (UAC)",
        "smartscreen" => "SmartScreen",
        "rdp" => "Escritorio remoto",
        "windows_update" => "Windows Update",
        "windows_update_reboot" => "Windows Update (reinicio)",
        "secure_boot" => "Arranque seguro (Secure Boot)",
        "bitlocker" => "Cifrado de disco (BitLocker)",
        "hosts" => "Archivo hosts",
        "dns" => "Servidor DNS",
        "proxy" => "Proxy",
        "proxy_pac" => "Script de proxy (PAC)",
        _ => name,
    };
}
