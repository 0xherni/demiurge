using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Demiurge.Core.Actions;
using Demiurge.Core.Collectors;
using Demiurge.Core.Enrichment;
using Demiurge.Core.External;
using Demiurge.Core.Intel;
using Demiurge.Core.Inventory;
using Demiurge.Core.Ipc;
using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Native;
using Demiurge.Core.Storage;
using Demiurge.Core.Text;

namespace Demiurge.Core;

/// <summary>
/// Raíz de composición del motor y API única (la usan el servicio vía named pipe y la CLI en modo local).
/// Valida todas las operaciones del lado servicio.
/// </summary>
public sealed class DemiurgeEngine : IAsyncDisposable
{
    public DemiurgeOptions Options { get; }
    public DemiurgeDb Db { get; }
    public FeedStore Feeds { get; }
    public KnowledgeBase Kb { get; }
    public TextCatalog Text { get; }
    public ScanOrchestrator Orchestrator { get; }
    public ActionService Actions { get; }

    private readonly HttpClient _http;
    private readonly FeedUpdater _feedUpdater;
    private readonly ILogger _logger;
    private ScanSnapshot? _latest;
    private CancellationTokenSource? _scanCts;
    private ScanProgress? _lastProgress;

    /// <summary>Mensajes push hacia los clientes conectados: (evento, datos).</summary>
    public event Action<string, JsonNode?>? Push;

    public DemiurgeEngine(ILogger logger)
    {
        _logger = logger;
        // Antes de leer cualquier archivo de datos: proteger la carpeta y apartar lo que haya plantado otro usuario.
        Security.DataDirectoryLockdown.Apply(Util.DemiurgePaths.Root, logger);
        Options = DemiurgeOptions.Load();
        Db = new DemiurgeDb();
        Feeds = new FeedStore(logger);
        Kb = KnowledgeBase.Load();
        Text = new TextCatalog(Options.Language);

        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(60), MaxResponseContentBufferSize = 200L * 1024 * 1024 };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"Demiurge/{ScanOrchestrator.AppVersion} (+home security dashboard)");
        _feedUpdater = new FeedUpdater(_http, Options, logger);


        var reputation = new ReputationService(_http, Db, Feeds, Options, logger);
        Orchestrator = new ScanOrchestrator(Options, Db, Feeds, Kb, Text, reputation, logger);
        Actions = new ActionService(Db, logger);
    }

    public void Start()
    {
        Feeds.Load();
        try
        {
            _latest = Db.LoadScan();
            // Re-evaluar con las reglas, allowlist y respuestas actuales (pueden haber cambiado desde el escaneo).
            if (_latest is not null) Orchestrator.Analyze(_latest);
        }
        catch (Exception ex) { _logger.LogWarning(ex, "No se pudo cargar el último escaneo"); }
    }

    /// <summary>Actualiza feeds (al iniciar y cada N horas). Funciona offline con la última copia.</summary>
    public async Task UpdateFeedsAsync(bool force, CancellationToken ct)
    {
        var changed = await _feedUpdater.UpdateAsync(force, ct).ConfigureAwait(false);
        if (Options.YaraX.Enabled) changed |= await YaraXScanner.UpdateRulesAsync(_http, _logger, ct).ConfigureAwait(false);
        if (changed || Feeds.LastLoaded is null) Feeds.Load();
    }

    public ScanSnapshot? Latest => _latest;

    public async Task<ScanSnapshot> ScanAsync(ScanType type, CancellationToken ct)
    {
        _scanCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var progress = new Progress<ScanProgress>(p =>
        {
            _lastProgress = p;
            Push?.Invoke("progress", JsonSerializer.SerializeToNode(p, Protocol.Json));
        });
        try
        {
            var snapshot = await Orchestrator.RunAsync(type, progress, _scanCts.Token).ConfigureAwait(false);
            _latest = snapshot;
            Push?.Invoke("scan_done", JsonSerializer.SerializeToNode(Summary(snapshot), Protocol.Json));
            return snapshot;
        }
        finally
        {
            _scanCts.Dispose();
            _scanCts = null;
        }
    }

    // ---------------------------------------------------------------- API

    public async Task<JsonNode?> HandleAsync(IpcRequest req, CallerInfo caller, CancellationToken ct)
    {
        if (!Protocol.Operations.Contains(req.Op)) throw new InvalidOperationException($"Operación no permitida: {req.Op}");
        Authorize(req.Op, caller);
        object? result = req.Op switch
        {
            "ping" => new
            {
                version = ScanOrchestrator.AppVersion,
                protocol = Protocol.Version,
                elevated = ProcessNative.IsAdministrator(),
                scanning = Orchestrator.IsScanning,
                feeds = Feeds.Version,
                kb = Kb.Version,
            },
            "scan.start" => StartScan(req),
            "scan.cancel" => CancelScan(),
            "scan.status" => new { scanning = Orchestrator.IsScanning, progress = _lastProgress },
            "scan.latest" => _latest is null ? null : Summary(_latest),
            "scan.list" => Db.ListScans(),
            "scan.get" => LoadScan(req) is { } s ? Summary(s) : null,
            "findings.list" => FindingsList(req),
            "entity.detail" => EntityDetail(req),
            "inventory" => Inventory(req),
            "diff" => RequireLatest(req) is { } d ? Orchestrator.Diff(d) : null,
            "plan" => Story.CleanupPlanBuilder.Build(RequireLatest(req), Db.GetActions(500), Text),
            "timeline" => Story.TimelineBuilder.Build(RequireLatest(req), Db.GetActions(500)),
            "answer" => Answer(req),
            "finding.state" => SetFindingState(req),
            "action.execute" => ExecuteAction(req),
            "action.revert" => RevertAction(req),
            "action.list" => Db.GetActions(),
            "allowlist.list" => Db.GetAllowlist(),
            "allowlist.remove" => RemoveAllowlist(req),
            "feeds.update" => await UpdateFeedsForApi(ct).ConfigureAwait(false),
            "config.get" => PublicConfig(),
            "config.set" => SetConfig(req),
            "tools.pin" => PinTool(req),
            _ => throw new InvalidOperationException("Operación no implementada"),
        };
        return result is null ? null : JsonSerializer.SerializeToNode(result, result.GetType(), Protocol.Json);
    }

    /// <summary>
    /// Autorización por operación según el token del proceso que llama (identificado por el kernel vía el pipe).
    /// </summary>
    private void Authorize(string op, CallerInfo caller)
    {
        if (caller.InProcess || Protocol.PublicOperations.Contains(op) || caller.Elevated) return;
        if (Protocol.ReadOperations.Contains(op) && Options.AllowUnelevatedReads) return;
        _logger.LogWarning("Pedido '{Op}' rechazado: el proceso {Image} (PID {Pid}, {User}) no está elevado", op, caller.Image, caller.Pid, caller.User);
        throw new UnauthorizedAccessException("Esta operación necesita permisos de administrador. Abrí Demiurge y aceptá el aviso de Windows (UAC).");
    }

    private object StartScan(IpcRequest req)
    {
        if (Orchestrator.IsScanning) throw new InvalidOperationException("Ya hay un escaneo en curso.");
        var type = Enum.TryParse<ScanType>(req.Str("type") ?? "Completo", true, out var t) && t != ScanType.Vivo ? t : ScanType.Completo;
        _ = Task.Run(async () =>
        {
            try { await ScanAsync(type, CancellationToken.None).ConfigureAwait(false); }
            catch (OperationCanceledException) { Push?.Invoke("scan_cancelled", null); }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Escaneo falló");
                Push?.Invoke("scan_error", JsonValue.Create(ex.Message));
            }
        });
        return new { started = true, type };
    }

    private object CancelScan()
    {
        _scanCts?.Cancel();
        return new { cancelled = _scanCts is not null };
    }

    private ScanSnapshot? LoadScan(IpcRequest req)
    {
        if (req.Long("scanId") is not long id || id == _latest?.Scan.Id) return _latest;
        var s = Db.LoadScan(id);
        if (s is not null) Orchestrator.Analyze(s);
        return s;
    }

    private ScanSnapshot RequireLatest(IpcRequest req) =>
        LoadScan(req) ?? throw new InvalidOperationException("Todavía no hay escaneos. Corré uno primero.");

    /// <summary>Capa 1: veredicto global, salud y conteos.</summary>
    public object Summary(ScanSnapshot s) => new
    {
        scanId = s.Scan.Id,
        started = s.Scan.Started,
        finished = s.Scan.Finished,
        type = s.Scan.Type,
        verdict = s.Verdict,
        verdictText = s.VerdictText,
        verdictIcon = s.Verdict switch { GlobalVerdict.Limpio => "🟢", GlobalVerdict.Revisar => "🟡", _ => "🔴" },
        disclaimer = Text["verdict.disclaimer"],
        immediate = s.Verdict == GlobalVerdict.ProbableInfeccion ? Text["verdict.immediate"] : null,
        elevatedWarning = s.Scan.Elevated ? null : Text["verdict.noadmin"],
        scoreMax = s.Scan.ScoreMax,
        health = new
        {
            s.Health.Level,
            s.Health.Summary,
            items = s.Health.Items.Select(i => new { i.Name, label = Demiurge.Core.Inventory.InventoryBuilder.SettingLabel(i.Name), i.Value, i.Ok, text = i.Ok == false ? Text.Get($"health.{i.Name}", ("value", i.Value)) : null }),
            issues = s.Health.Items.Where(i => i.Ok == false).Select(i => new { i.Name, label = Demiurge.Core.Inventory.InventoryBuilder.SettingLabel(i.Name), i.Value, text = Text.Get($"health.{i.Name}", ("value", i.Value)) }),
        },
        defender = new
        {
            available = s.Defender.Available,
            realTime = s.Defender.RealTimeProtectionEnabled,
            otherAv = s.Defender.OtherAntivirus,
            // Lo que Defender ya detectó en los últimos 30 días: si el archivo ya no está, está resuelto.
            recent = s.Defender.Detections
                .Where(d => d.Time is null || d.Time >= DateTimeOffset.Now.AddDays(-30))
                .OrderByDescending(d => d.Time)
                .Take(10)
                .Select(d =>
                {
                    var paths = Rules.Heuristics.DefenderFilePaths(d).ToList();
                    return new { threat = d.ThreatName, time = d.Time, paths, stillPresent = paths.Any(File.Exists) };
                }),
        },
        counts = new
        {
            danger = s.Scores.Count(x => x.Level == EntityLevel.Peligroso),
            review = s.Scores.Count(x => x.Level == EntityLevel.Revisar),
            questions = s.Scores.Count(x => x.PendingQuestion is not null),
            processes = s.Processes.Count(p => p.EndTime is null),
            startup = s.Persistence.Count,
            connections = s.Connections.Count,
            extensions = s.Extensions.Count,
            software = s.Software.Count,
        },
        findings = s.Scores.Where(x => x.Level != EntityLevel.Info || x.PendingQuestion is not null).Take(50),
        collectors = s.Collectors.OrderBy(c => c.Id),
        feeds = Feeds.LastLoaded is null ? s.Scan.FeedsVersion : Feeds.Version, // estado actual de la inteligencia
    };

    /// <summary>Capa 2: tarjetas de entidades con score ≥ 20 (o con pregunta pendiente), ordenadas por score.</summary>
    private object FindingsList(IpcRequest req)
    {
        var s = RequireLatest(req);
        bool all = req.Bool("all");
        return s.Scores.Where(x => all || x.Level != EntityLevel.Info || x.PendingQuestion is not null);
    }

    /// <summary>"Ver detalle técnico": entidad → findings → datos crudos.</summary>
    private object EntityDetail(IpcRequest req)
    {
        var s = RequireLatest(req);
        var key = req.Str("key") ?? throw new ArgumentException("Falta 'key'");
        var score = s.Scores.FirstOrDefault(x => x.ScoringKey == key);
        var findings = s.Findings.Where(f => f.ScoringKey == key || f.EntityKey == key).ToList();
        var bin = s.GetBinary(key) ?? s.GetBinary(findings.Select(f => f.ScoringKey).FirstOrDefault(k => s.GetBinary(k) is not null));
        var processes = s.Processes.Where(p => p.Key == key || (bin is not null && p.BinaryKey == bin.Key)).ToList();
        var pids = processes.Select(p => p.Pid).ToHashSet();
        var kb = Kb.MatchBinary(bin);

        return new
        {
            score,
            findings,
            binary = bin,
            knowledge = kb?.Entry,
            processes,
            processTree = processes.Select(p => Ancestry(s, p)).ToList(),
            persistence = s.Persistence.Where(p => p.Key == key || (bin is not null && p.BinaryKey == bin.Key)),
            connections = s.Connections.Where(c => pids.Contains(c.Pid) || c.Key == key),
            dns = s.DnsQueries.Where(d => d.Pid is int pid && pids.Contains(pid) || d.Key == key),
            modules = s.ModuleLoads.Where(m => pids.Contains(m.Pid) || (bin is not null && m.BinaryKey == bin.Key)),
            entity = s.AllEntities().FirstOrDefault(e => e.Key == key),
            attack = findings.SelectMany(f => f.AttackIds).Distinct().OrderBy(x => x),
        };
    }

    private static List<string> Ancestry(ScanSnapshot s, ProcessInfo p)
    {
        var chain = new List<string> { $"{p.Name} ({p.Pid})" };
        var byPid = s.Processes.Where(x => x.EndTime is null).GroupBy(x => x.Pid).ToDictionary(g => g.Key, g => g.First());
        var cur = p;
        for (int i = 0; i < 12 && byPid.TryGetValue(cur.ParentPid, out var parent) && parent.Pid != cur.Pid; i++)
        {
            if (parent.StartTime is not null && cur.StartTime is not null && parent.StartTime > cur.StartTime) break;
            chain.Insert(0, $"{parent.Name} ({parent.Pid})");
            cur = parent;
        }
        return chain;
    }

    private object Inventory(IpcRequest req)
    {
        var s = RequireLatest(req);
        var tab = req.Str("tab") ?? "startup";
        if (!InventoryBuilder.Tabs.Contains(tab)) throw new ArgumentException($"Pestaña desconocida: {tab}");
        return new InventoryBuilder(Kb, Text).Build(s, tab, req.Str("search"));
    }

    private object? Answer(IpcRequest req)
    {
        var key = req.Str("entityKey") ?? throw new ArgumentException("Falta 'entityKey'");
        var question = req.Str("questionId") ?? throw new ArgumentException("Falta 'questionId'");
        var answer = req.Str("answer") ?? throw new ArgumentException("Falta 'answer'");
        Db.SaveAnswer(new UserAnswer { EntityKey = key, QuestionId = question, Answer = answer, Date = DateTimeOffset.Now });
        return Reanalyze(key);
    }

    private object? SetFindingState(IpcRequest req)
    {
        var h = req.Str("heuristicId") ?? throw new ArgumentException("Falta 'heuristicId'");
        var key = req.Str("entityKey") ?? throw new ArgumentException("Falta 'entityKey'");
        var state = Enum.Parse<FindingState>(req.Str("state") ?? "Visto", true);
        Db.SetFindingState(h, key, state);
        return Reanalyze(key);
    }

    private object ExecuteAction(IpcRequest req)
    {
        var s = RequireLatest(req);
        var r = Actions.Execute(new ActionRequest
        {
            Action = req.Str("action") ?? "",
            EntityKey = req.Str("entityKey") ?? "",
            Confirmed = req.Bool("confirmed"),
            Note = req.Str("note"),
        }, s);
        if (r.Success && req.Str("action") == "allowlist") Reanalyze(req.Str("entityKey")!);
        return r;
    }

    private object RevertAction(IpcRequest req)
    {
        var r = Actions.Revert(req.Str("id") ?? throw new ArgumentException("Falta 'id'"));
        if (r.Success && _latest is not null) Reanalyze(null);
        return r;
    }

    private object RemoveAllowlist(IpcRequest req)
    {
        var key = req.Str("entityKey") ?? throw new ArgumentException("Falta 'entityKey'");
        var removed = Db.RemoveAllowlist(key);
        Reanalyze(key);
        return new { removed };
    }

    /// <summary>Recalcula reglas y scoring del último escaneo sin volver a recolectar (respuestas, allowlist).</summary>
    private object? Reanalyze(string? key)
    {
        if (_latest is null) return null;
        Orchestrator.Analyze(_latest);
        return key is null ? Summary(_latest) : _latest.Scores.FirstOrDefault(x => x.ScoringKey == key) ?? (object)Summary(_latest);
    }

    private async Task<object> UpdateFeedsForApi(CancellationToken ct)
    {
        await UpdateFeedsAsync(true, ct).ConfigureAwait(false);
        return new { feeds = Feeds.Version, ips = Feeds.Ips.Count, domains = Feeds.Domains.Count, hashes = Feeds.Hashes.Count, lolbas = Feeds.Lolbas.Count, roots = Feeds.AuthRootThumbprints.Count };
    }

    private object PublicConfig() => new
    {
        Options.OnlineHashLookups,
        virusTotalConfigured = !string.IsNullOrEmpty(Options.VirusTotalApiKey),
        abuseChConfigured = !string.IsNullOrEmpty(Options.AbuseChAuthKey),
        Options.FeedUpdateHours,
        Options.EventLogDays,
        Options.RecentFilesDays,
        Options.DefenderScanEnabled,
        defenderAvailable = DefenderScanner.Locate() is not null,
        yaraX = new { Options.YaraX.Enabled, path = ExternalRunner.ResolvePath(Options.YaraX), pinned = Options.YaraX.ExpectedSha256 is not null || ToolLock.Get(Options.YaraX.LockId) is not null, rules = YaraXScanner.HasRules(Options) },
        hollowsHunter = new { Options.HollowsHunter.Enabled, path = ExternalRunner.ResolvePath(Options.HollowsHunter), pinned = Options.HollowsHunter.ExpectedSha256 is not null || ToolLock.Get(Options.HollowsHunter.LockId) is not null },
        hayabusa = new { Options.Hayabusa.Enabled, path = ExternalRunner.ResolvePath(Options.Hayabusa), pinned = Options.Hayabusa.ExpectedSha256 is not null || ToolLock.Get(Options.Hayabusa.LockId) is not null },
        Options.SysmonOptIn,
        Options.AllowUnelevatedReads,
    };

    /// <summary>Sólo se permiten claves conocidas (validación del lado servicio).</summary>
    private object SetConfig(IpcRequest req)
    {
        var a = req.Args ?? new JsonObject();
        if (a["onlineHashLookups"] is JsonValue o && o.TryGetValue<bool>(out var ob)) Options.OnlineHashLookups = ob;
        if (a.ContainsKey("virusTotalApiKey"))
        {
            var vt = a["virusTotalApiKey"]?.ToString()?.Trim();
            // Las claves de VirusTotal son 64 caracteres hexadecimales: así se detecta una clave copiada a medias.
            if (!string.IsNullOrEmpty(vt) && !System.Text.RegularExpressions.Regex.IsMatch(vt, "^[0-9a-fA-F]{64}$"))
                throw new ArgumentException("Esa clave no parece completa: tiene que ser una tira de 64 letras y números. Copiala de nuevo desde tu perfil en virustotal.com.");
            Options.VirusTotalApiKey = string.IsNullOrEmpty(vt) ? null : vt;
        }
        if (a.ContainsKey("abuseChAuthKey")) Options.AbuseChAuthKey = a["abuseChAuthKey"]?.ToString() is { Length: > 0 } ab ? ab : null;
        if (a["feedUpdateHours"] is JsonValue f && f.TryGetValue<int>(out var fh)) Options.FeedUpdateHours = Math.Clamp(fh, 1, 168);
        if (a["yaraXEnabled"] is JsonValue y && y.TryGetValue<bool>(out var yb)) Options.YaraX.Enabled = yb;
        if (a["hollowsHunterEnabled"] is JsonValue h && h.TryGetValue<bool>(out var hb)) Options.HollowsHunter.Enabled = hb;
        if (a["hayabusaEnabled"] is JsonValue hy && hy.TryGetValue<bool>(out var hyb)) Options.Hayabusa.Enabled = hyb;
        if (a["allowUnelevatedReads"] is JsonValue ur && ur.TryGetValue<bool>(out var urb)) Options.AllowUnelevatedReads = urb;
        if (a["defenderScanEnabled"] is JsonValue ds && ds.TryGetValue<bool>(out var dsb)) Options.DefenderScanEnabled = dsb;
        Options.Save();
        return PublicConfig();
    }

    /// <summary>Fija el SHA256 del binario externo actual (el usuario confirma que lo descargó del sitio oficial).</summary>
    private object PinTool(IpcRequest req)
    {
        var tool = (req.Str("tool") ?? "").ToLowerInvariant() switch
        {
            "yarax" or "yara" or "yr" => Options.YaraX,
            "hollowshunter" or "hh" or "pesieve" => Options.HollowsHunter,
            "hayabusa" => Options.Hayabusa,
            _ => throw new ArgumentException("Herramienta desconocida (yarax | hollowshunter | hayabusa)"),
        };
        var path = ExternalRunner.ResolvePath(tool) ?? throw new FileNotFoundException($"Copiá {tool.FileName} a {Util.DemiurgePaths.Tools}");
        tool.ExpectedSha256 = FileHasher.Compute(path)?.Sha256;
        tool.Enabled = true;
        Options.Save();
        return new { path, sha256 = tool.ExpectedSha256 };
    }


    public async ValueTask DisposeAsync()
    {
        _http.Dispose();
        await Task.CompletedTask;
    }
}
