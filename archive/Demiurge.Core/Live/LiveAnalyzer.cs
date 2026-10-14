using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Demiurge.Core.Collectors;
using Demiurge.Core.Enrichment;
using Demiurge.Core.Intel;
using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Rules;
using Demiurge.Core.Text;

namespace Demiurge.Core.Live;

/// <summary>
/// Modo vivo: evalúa cada proceso, conexión, dominio y persistencia nuevos con las mismas heurísticas
/// del escaneo, y notifica cuando el score supera el umbral (08_UX_Explicaciones: "Modo vivo").
/// </summary>
public sealed class LiveAnalyzer : IDisposable
{
    private readonly LiveMonitor _monitor;
    private readonly FeedStore _feeds;
    private readonly KnowledgeBase _kb;
    private readonly TextCatalog _text;
    private readonly DemiurgeOptions _options;
    private readonly Func<ScanSnapshot?> _latest;
    private readonly ILogger _logger;

    private readonly ConcurrentQueue<LiveEvent> _recent = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alerted = new();
    private readonly System.Threading.Channels.Channel<Func<Task>> _work = System.Threading.Channels.Channel.CreateBounded<Func<Task>>(
        new System.Threading.Channels.BoundedChannelOptions(2000) { FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest });
    private HashSet<string>? _knownPersistence;
    private readonly CancellationTokenSource _cts = new();

    public event Action<LiveEvent>? Alert;

    public LiveAnalyzer(LiveMonitor monitor, FeedStore feeds, KnowledgeBase kb, TextCatalog text, DemiurgeOptions options,
        Func<ScanSnapshot?> latest, ILogger logger)
    {
        _monitor = monitor;
        _feeds = feeds;
        _kb = kb;
        _text = text;
        _options = options;
        _latest = latest;
        _logger = logger;
    }

    public IReadOnlyList<LiveEvent> Recent => _recent.Reverse().ToList();

    public void Start()
    {
        _monitor.ProcessStarted += p => Enqueue(() => OnProcess(p));
        _monitor.ProcessStopped += p => { if (p.Ephemeral) Enqueue(() => OnProcess(p)); };
        _monitor.NewFlow += f => Enqueue(() => OnFlow(f));
        _monitor.NewDomain += d => Enqueue(() => OnDomain(d));
        _monitor.ModuleLoaded += m => Enqueue(() => OnModule(m));
        _ = Task.Run(WorkLoop);
        _ = Task.Run(PersistenceLoop);
    }

    private void Enqueue(Func<Task> work) => _work.Writer.TryWrite(work);

    private async Task WorkLoop()
    {
        await foreach (var w in _work.Reader.ReadAllAsync(_cts.Token).ConfigureAwait(false))
        {
            try { await w().ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogDebug(ex, "Error en análisis en vivo"); }
        }
    }

    /// <summary>Snapshot mínimo: procesos del último escaneo (para padre/hijo) + la entidad nueva.</summary>
    private ScanSnapshot MiniSnapshot()
    {
        var latest = _latest();
        var s = new ScanSnapshot { Scan = new ScanInfo { Type = ScanType.Vivo, Started = DateTimeOffset.Now } };
        if (latest is not null)
        {
            s.Processes.AddRange(latest.Processes.Where(p => p.EndTime is null));
            foreach (var (k, b) in latest.Binaries) s.Binaries[k] = b;
            s.Defender = latest.Defender;
        }
        return s;
    }

    private List<Finding> Evaluate(ScanSnapshot s, Func<Finding, bool> relevant)
    {
        var rules = RuleSet.Load();
        var ctx = new RuleContext { Snapshot = s, Rules = rules, Kb = _kb, Feeds = _feeds };
        // Feeds locales por hash (online sólo en escaneos completos).
        foreach (var b in s.Binaries.Values.Where(b => b.Malicious is null))
        {
            var hit = _feeds.MatchHash(b.Sha256, b.Sha1, b.Md5);
            if (hit is not null) b.Reputation.Add(new ReputationInfo { Source = hit.Source, Verdict = "malicious", Family = hit.Family, Fetched = DateTimeOffset.Now });
        }
        var findings = new RulesEngine(_logger).Evaluate(ctx).Where(relevant).ToList();
        // Allowlist dura también en vivo.
        var ignores = rules.Scoring.HardAllowlistIgnores.ToHashSet();
        foreach (var f in findings.Where(f => ignores.Contains(f.HeuristicId)))
            if (ctx.IsHardAllowlisted(s.GetBinary(f.ScoringKey))) f.Weight = 0;
        return findings;
    }

    private Task OnProcess(ProcessInfo p)
    {
        var s = MiniSnapshot();
        var reg = new BinaryRegistry(s);
        p.BinaryKey = reg.Register(p.Path);
        s.Processes.RemoveAll(x => x.Pid == p.Pid);
        s.Processes.Add(p);
        var findings = Evaluate(s, f => f.EntityKey == p.Key || f.ScoringKey == p.BinaryKey);
        Raise("process", findings, p.BinaryKey ?? p.Key, p.Name, p.CommandLine ?? p.Path ?? "");
        return Task.CompletedTask;
    }

    private Task OnFlow(NetworkFlow f)
    {
        if (!RuleContext.IsPublicIp(f.RemoteAddress)) return Task.CompletedTask;
        var hit = _feeds.MatchIp(f.RemoteAddress, f.RemotePort);
        if (hit is null) return Task.CompletedTask;
        var def = RuleSet.Load()["H-02"];
        if (def is null) return Task.CompletedTask;
        var detail = $"{f.ProcessName ?? $"PID {f.Pid}"} → {f.RemoteAddress}:{f.RemotePort} ({hit.Source}: {hit.Family ?? hit.Category})";
        RaiseRaw("connection", def.Weight, ["H-02"], $"{f.Pid}|{f.RemoteAddress}", f.ProcessName ?? "?", detail);
        return Task.CompletedTask;
    }

    private Task OnDomain(DnsQueryInfo d)
    {
        var hit = _feeds.MatchDomain(d.Domain);
        if (hit is null) return Task.CompletedTask;
        var def = RuleSet.Load()["H-02"];
        if (def is null) return Task.CompletedTask;
        RaiseRaw("dns", def.Weight, ["H-02"], "dns:" + d.Domain, d.ProcessName ?? "Tu PC", $"{d.Domain} ({hit.Source}: {hit.Family ?? hit.Category})");
        return Task.CompletedTask;
    }

    private Task OnModule(ModuleLoadInfo m)
    {
        var s = MiniSnapshot();
        m.BinaryKey = new BinaryRegistry(s).Register(m.Path);
        s.ModuleLoads.Add(m);
        var findings = Evaluate(s, f => f.EntityKey == m.Key || f.ScoringKey == m.BinaryKey);
        Raise("module", findings, m.BinaryKey ?? m.Key, Path.GetFileName(m.Path), $"{m.ProcessName} cargó {m.Path}");
        return Task.CompletedTask;
    }

    /// <summary>Cada 5 minutos revisa entradas de arranque nuevas (registro, Inicio, tareas, servicios, WMI).</summary>
    private async Task PersistenceLoop()
    {
        var collectors = new ICollector[]
        {
            new RegistryPersistenceCollector(), new StartupFolderCollector(), new ScheduledTaskCollector(),
            new ServiceCollector(), new WmiPersistenceCollector(),
        };
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(5), _cts.Token).ConfigureAwait(false);
                var s = MiniSnapshot();
                var ctx = new ScanContext { Snapshot = s, Options = _options, Binaries = new BinaryRegistry(s), Logger = _logger, ScanType = ScanType.Vivo };
                foreach (var c in collectors)
                {
                    try { await c.CollectAsync(ctx, _cts.Token).ConfigureAwait(false); }
                    catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogDebug("{Id}: {Error}", c.Id, ex.Message); }
                }

                var baseline = _knownPersistence ?? _latest()?.Persistence.Select(p => p.Key).ToHashSet();
                var current = s.Persistence.Select(p => p.Key).ToHashSet();
                if (baseline is not null)
                {
                    var added = s.Persistence.Where(p => !baseline.Contains(p.Key)).ToList();
                    if (added.Count > 0)
                    {
                        var keys = added.Select(a => a.Key).ToHashSet();
                        var bins = added.Select(a => a.BinaryKey).Where(k => k is not null).ToHashSet();
                        var findings = Evaluate(s, f => keys.Contains(f.EntityKey) || bins.Contains(f.ScoringKey));
                        foreach (var item in added)
                        {
                            var mine = findings.Where(f => f.EntityKey == item.Key || f.ScoringKey == item.BinaryKey).ToList();
                            // Toda persistencia nueva se informa; con score alto, como alerta.
                            if (mine.Sum(f => f.Weight) == 0)
                                RaiseRaw("persistence", 0, [], item.Key, item.DisplayName, $"{item.Type}: {item.Command}", notify: false);
                            else
                                Raise("persistence", mine, item.BinaryKey ?? item.Key, item.DisplayName, $"{item.Type}: {item.Command}");
                        }
                    }
                }
                _knownPersistence = current;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Chequeo de persistencia en vivo falló");
            }
        }
    }

    private void Raise(string type, List<Finding> findings, string key, string name, string detail)
    {
        var score = findings.GroupBy(f => f.HeuristicId).Sum(g => g.Max(f => f.Weight));
        if (findings.Any(f => f.Severity == Severity.Critica && f.Weight > 0)) score = Math.Max(score, 100);
        if (score < _options.LiveAlertThreshold) return;
        RaiseRaw(type, score, findings.Where(f => f.Weight > 0).Select(f => f.HeuristicId).Distinct().ToList(), key, name,
            detail + " — " + string.Join(" ", findings.Where(f => f.Weight > 0).Select(f => f.Explanation).Distinct()));
    }

    private void RaiseRaw(string type, int score, List<string> heuristics, string key, string name, string detail, bool notify = true)
    {
        // No repetir la misma alerta más de una vez por hora.
        if (_alerted.TryGetValue(type + key, out var last) && DateTimeOffset.Now - last < TimeSpan.FromHours(1)) return;
        _alerted[type + key] = DateTimeOffset.Now;
        var e = new LiveEvent
        {
            Type = type,
            Title = $"{_text[$"live.{type}"]}: {name}",
            Detail = detail.Length > 500 ? detail[..500] + "…" : detail,
            Score = score,
            HeuristicIds = heuristics,
            EntityKey = key,
        };
        _recent.Enqueue(e);
        while (_recent.Count > 500) _recent.TryDequeue(out _);
        if (notify) Alert?.Invoke(e);
        _logger.LogInformation("Modo vivo [{Type}] {Title} (score {Score})", type, e.Title, score);
    }

    public void Dispose() => _cts.Cancel();
}
