using System.Reflection;
using Microsoft.Extensions.Logging;
using Demiurge.Core.Collectors;
using Demiurge.Core.Diff;
using Demiurge.Core.Enrichment;
using Demiurge.Core.External;
using Demiurge.Core.Intel;
using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Native;
using Demiurge.Core.Rules;
using Demiurge.Core.Scoring;
using Demiurge.Core.Storage;
using Demiurge.Core.Text;

namespace Demiurge.Core;

/// <summary>
/// Orquesta un escaneo: colectores → enriquecimiento (firma, hash, reputación, feeds) → reglas →
/// scoring → (herramientas externas → re-análisis) → persistencia del snapshot.
/// </summary>
public sealed class ScanOrchestrator
{
    public static string AppVersion { get; } = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";

    private readonly DemiurgeOptions _options;
    private readonly DemiurgeDb _db;
    private readonly FeedStore _feeds;
    private readonly KnowledgeBase _kb;
    private readonly TextCatalog _text;
    private readonly ReputationService _reputation;
    private readonly ExternalRunner _runner;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _scanLock = new(1);

    public ScanOrchestrator(DemiurgeOptions options, DemiurgeDb db, FeedStore feeds, KnowledgeBase kb, TextCatalog text,
        ReputationService reputation, ILogger logger)
    {
        _options = options;
        _db = db;
        _feeds = feeds;
        _kb = kb;
        _text = text;
        _reputation = reputation;
        _logger = logger;
        _runner = new ExternalRunner(logger);
    }

    public bool IsScanning => _scanLock.CurrentCount == 0;

    public static IEnumerable<ICollector> CreateCollectors() =>
    [
        new ProcessCollector(),                 // COL-01
        new DnsCollector(),                     // COL-05/16
        new RegistryPersistenceCollector(),     // COL-08
        new StartupFolderCollector(),           // COL-09
        new ScheduledTaskCollector(),           // COL-10
        new ServiceCollector(),                 // COL-11
        new WmiPersistenceCollector(),          // COL-12
        new OtherPersistenceCollector(),        // COL-13
        new NetworkConnectionCollector(),       // COL-14
        new NetworkConfigCollector(),           // COL-15
        new DefenderCollector(),                // COL-17
        new SecurityPostureCollector(),         // COL-18
        new AccountCollector(),                 // COL-19
        new CertificateCollector(),             // COL-20
        new InstalledSoftwareCollector(),       // COL-21
        new BrowserCollector(),                 // COL-22
        new EventLogCollector(),                // COL-23
        new DriverCollector(),                  // COL-24
        new RecentFilesCollector(),             // COL-25
        new ExecutionHistoryCollector(),        // COL-27
        new FirewallCollector(),                // COL-28
        new ResourceCollector(),                // COL-26
    ];

    public async Task<ScanSnapshot> RunAsync(ScanType type, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        if (!await _scanLock.WaitAsync(0, ct).ConfigureAwait(false))
            throw new InvalidOperationException("Ya hay un escaneo en curso.");
        try
        {
            var snapshot = new ScanSnapshot
            {
                Scan = new ScanInfo
                {
                    Started = DateTimeOffset.Now,
                    Type = type,
                    AppVersion = AppVersion,
                    FeedsVersion = _feeds.Version,
                    Elevated = ProcessNative.IsAdministrator(),
                    Machine = Environment.MachineName,
                },
            };
            progress?.Report(new ScanProgress("start", _text["verdict.disclaimer"], 1));

            var ctx = new ScanContext
            {
                Snapshot = snapshot,
                Options = _options,
                Binaries = new BinaryRegistry(snapshot),
                Logger = _logger,
                ScanType = type,
                Progress = progress,
            };
            await new CollectorRunner(CreateCollectors()).RunAsync(ctx, ct).ConfigureAwait(false);

            if (_options.SysmonOptIn)
            {
                var history = SysmonIntegration.ReadProcessHistory(_options.EventLogDays);
                foreach (var p in history) p.BinaryKey = ctx.Binaries.Register(p.Path);
                snapshot.Processes.AddRange(history);
            }

            progress?.Report(new ScanProgress("enrich", "Reputación y firmas", 78));
            try { await _reputation.EnrichAsync(snapshot, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogWarning(ex, "Enriquecimiento de reputación incompleto"); }

            progress?.Report(new ScanProgress("analyze", "Evaluando señales", 85));
            Analyze(snapshot);

            await RunExternalToolsAsync(snapshot, type, progress, ct).ConfigureAwait(false);

            snapshot.Scan.Finished = DateTimeOffset.Now;
            _db.SaveScan(snapshot);
            _db.Prune();
            progress?.Report(new ScanProgress("done", snapshot.VerdictText, 100));
            _logger.LogInformation("Escaneo {Id} terminado: {Verdict} (score máx {Score}, {Findings} findings, {Entities} entidades a revisar)",
                snapshot.Scan.Id, snapshot.Verdict, snapshot.Scan.ScoreMax, snapshot.Findings.Count, snapshot.Scores.Count(s => s.Level != EntityLevel.Info));
            return snapshot;
        }
        finally
        {
            _scanLock.Release();
        }
    }

    /// <summary>Evalúa reglas y scoring sobre un snapshot (también se usa al responder preguntas o marcar "lo reconozco").</summary>
    public void Analyze(ScanSnapshot snapshot)
    {
        var rules = RuleSet.Load();
        var previous = snapshot.Scan.Id > 0 ? _db.LoadPreviousScan(snapshot.Scan.Id) : _db.LoadScan();
        var answers = _db.GetAnswers().ToDictionary(a => $"{a.EntityKey}|{a.QuestionId}");

        var ruleCtx = new RuleContext
        {
            Snapshot = snapshot,
            Previous = previous,
            Rules = rules,
            Kb = _kb,
            Feeds = _feeds,
            Answers = answers,
        };
        AnnotateKnowledge(snapshot);
        snapshot.Findings = new RulesEngine(_logger).Evaluate(ruleCtx);

        new ScoringEngine(_text, _kb).Score(new ScoringEngine.Inputs
        {
            Snapshot = snapshot,
            Rules = rules,
            Context = ruleCtx,
            UserAllowlist = _db.GetAllowlist().Select(a => a.EntityKey).ToHashSet(),
            FindingStates = _db.GetFindingStates(),
            PreviousFindingKeys = previous?.Findings.Select(f => $"{f.HeuristicId}|{f.EntityKey}").ToHashSet() ?? new(),
        });
    }

    public DiffReport Diff(ScanSnapshot snapshot) =>
        ScanDiff.Compute(snapshot, snapshot.Scan.Id > 0 ? _db.LoadPreviousScan(snapshot.Scan.Id) : _db.LoadScan(), _text);

    private void AnnotateKnowledge(ScanSnapshot s)
    {
        foreach (var b in s.Binaries.Values) b.KbId ??= _kb.MatchBinary(b)?.Entry.Id;
        foreach (var sw in s.Software)
        {
            var kb = _kb.MatchSoftware(sw);
            if (kb is null) continue;
            sw.KbId = kb.Id;
            if (kb.Category is "remote_tool" or "pup") sw.Category = kb.Category;
        }
    }

    /// <summary>
    /// Motores de detección, después de un primer análisis (así se sabe qué es sospechoso):
    ///  1. YARA-X: programas en ejecución, lo que arranca solo, descargas recientes y todo lo sospechoso
    ///     (escaneo profundo: todos los binarios no firmados por Microsoft).
    ///  2. HollowsHunter: memoria de los procesos sospechosos (escaneo profundo: todos).
    ///  3. Re-análisis, y Microsoft Defender sobre lo que quedó sospechoso + lo que marcó YARA: confirma qué es.
    ///  4. Hayabusa (opcional, sólo escaneo profundo).
    /// </summary>
    private async Task RunExternalToolsAsync(ScanSnapshot s, ScanType type, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        bool deep = type == ScanType.Profundo;
        bool any = false;
        var suspiciousKeys = s.Scores.Where(x => x.Score > 0).Select(x => x.ScoringKey).ToHashSet();

        bool Trusted(BinaryInfo b) => b.Signature?.IsMicrosoft == true || b.IsKnownGood || _kb.MatchBinary(b)?.Trusted == true;

        if (_options.YaraX.Enabled && YaraXScanner.HasRules(_options))
        {
            var interesting = new HashSet<string>();
            foreach (var p in s.Processes) if (p.BinaryKey is not null) interesting.Add(p.BinaryKey);
            foreach (var p in s.Persistence) if (p.BinaryKey is not null) interesting.Add(p.BinaryKey);
            foreach (var f in s.RecentFiles) if (f.BinaryKey is not null) interesting.Add(f.BinaryKey);
            foreach (var x in s.Executions) if (x.BinaryKey is not null) interesting.Add(x.BinaryKey);
            interesting.UnionWith(suspiciousKeys);
            var targets = s.Binaries.Values
                .Where(b => b.Exists && !(b.Signature?.IsMicrosoft == true) && (deep || (interesting.Contains(b.Key) && !Trusted(b))))
                .Select(b => b.Path).Take(deep ? 3000 : 600).ToList();
            progress?.Report(new ScanProgress("external", $"Buscando firmas de malware (YARA) en {targets.Count} archivos", 86));
            var dets = await new YaraXScanner(_runner, _options, _logger).ScanAsync(targets, ct).ConfigureAwait(false);
            s.ExternalDetections.AddRange(dets);
            any |= dets.Count > 0;
        }

        if (_options.HollowsHunter.Enabled)
        {
            IReadOnlyCollection<int>? pids = deep ? null : s.Processes
                .Where(p => p.EndTime is null && (suspiciousKeys.Contains(p.Key) || (p.BinaryKey is not null && suspiciousKeys.Contains(p.BinaryKey))))
                .Select(p => p.Pid).Distinct().ToList();
            if (deep || pids!.Count > 0)
            {
                progress?.Report(new ScanProgress("external", "Revisando la memoria de los programas", 90));
                var dets = await new HollowsHunterScanner(_runner, _options, _logger).ScanAsync(pids, ct).ConfigureAwait(false);
                s.ExternalDetections.AddRange(dets);
                any |= dets.Count > 0;
            }
        }

        if (any) Analyze(s);

        if (_options.DefenderScanEnabled)
        {
            var yaraHits = s.ExternalDetections.Where(d => d.Tool == "EXT-01" && d.TargetPath is not null).Select(d => d.TargetPath!);
            var suspicious = s.Scores.Where(x => x.Score > 0).Select(x => s.GetBinary(x.ScoringKey)).OfType<BinaryInfo>()
                .Where(b => b.Exists && b.Signature?.IsMicrosoft != true).Select(b => b.Path);
            var files = yaraHits.Concat(suspicious).Distinct(StringComparer.OrdinalIgnoreCase).Take(deep ? 150 : 40).ToList();
            if (files.Count > 0)
            {
                var defProgress = new Progress<string>(m => progress?.Report(new ScanProgress("external", m, 94)));
                progress?.Report(new ScanProgress("external", $"Pidiéndole a Microsoft Defender que analice {files.Count} archivo(s)", 93));
                var dets = await new DefenderScanner(_runner, _logger).ScanAsync(files, defProgress, ct).ConfigureAwait(false);
                s.ExternalDetections.AddRange(dets);
                Analyze(s);
            }
        }

        if (_options.Hayabusa.Enabled)
        {
            progress?.Report(new ScanProgress("external", "Revisando los registros de eventos de Windows (Sigma)", 96));
            var dets = await new HayabusaScanner(_runner, _options, _logger).ScanAsync(deep ? 30 : _options.EventLogDays, ct).ConfigureAwait(false);
            s.ExternalDetections.AddRange(dets);
            if (dets.Count > 0) Analyze(s);
        }
    }
}
