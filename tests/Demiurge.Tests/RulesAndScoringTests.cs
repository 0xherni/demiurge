using Microsoft.Extensions.Logging.Abstractions;
using Demiurge.Core.Intel;
using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Rules;
using Demiurge.Core.Scoring;
using Demiurge.Core.Text;

namespace Demiurge.Tests;

public class RulesAndScoringTests
{
    private static readonly string Win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string AppData = @"C:\Users\test\AppData\Roaming";

    private static BinaryInfo Bin(string path, bool signed, string? signer = null, string? sha = null) => new()
    {
        Path = path,
        Sha256 = sha ?? Guid.NewGuid().ToString("N"),
        Signature = new SignatureInfo { IsSigned = signed, IsValid = signed, Signer = signer },
    };

    private static (ScanSnapshot snap, RuleContext ctx) Analyze(ScanSnapshot s, FeedStore? feeds = null, Dictionary<string, UserAnswer>? answers = null)
    {
        var rules = RuleSet.Load();
        var kb = KnowledgeBase.Load();
        var ctx = new RuleContext { Snapshot = s, Rules = rules, Kb = kb, Feeds = feeds ?? new FeedStore(NullLogger.Instance), Answers = answers ?? new() };
        s.Findings = new RulesEngine(NullLogger.Instance).Evaluate(ctx);
        new ScoringEngine(new TextCatalog(), kb).Score(new ScoringEngine.Inputs { Snapshot = s, Rules = rules, Context = ctx });
        return (s, ctx);
    }

    [Fact]
    public void Embedded_rules_load_and_every_heuristic_has_an_evaluator()
    {
        var rules = RuleSet.Load();
        Assert.Equal(40, rules.Heuristics.Count);
        foreach (var h in rules.Heuristics)
            Assert.True(Heuristics.All.ContainsKey(h.Id), $"Sin evaluador: {h.Id}");
        Assert.Equal(20, rules.Scoring.ReviewMin);
        Assert.Equal(60, rules.Scoring.DangerMin);
        Assert.Contains("powershell.exe", rules["H-07"]!.Map("patterns").Keys);
    }

    [Fact]
    public void Clean_snapshot_is_Limpio()
    {
        var s = new ScanSnapshot();
        var b = Bin(Path.Combine(Win, "explorer.exe"), true, "Microsoft Windows");
        s.Binaries[b.Key] = b;
        s.Processes.Add(new ProcessInfo { Pid = 100, Name = "explorer.exe", Path = b.Path, BinaryKey = b.Key });
        var (snap, _) = Analyze(s);
        Assert.Equal(GlobalVerdict.Limpio, snap.Verdict);
        Assert.Equal("No encontramos indicadores de infección", snap.VerdictText);
    }

    [Fact]
    public void Single_unsigned_binary_stays_Info()
    {
        var s = new ScanSnapshot();
        var b = Bin(@"C:\Program Files\Tool\tool.exe", false);
        s.Binaries[b.Key] = b;
        s.Processes.Add(new ProcessInfo { Pid = 200, Name = "tool.exe", Path = b.Path, BinaryKey = b.Key });
        var (snap, _) = Analyze(s);
        var score = Assert.Single(snap.Scores);
        Assert.Equal(EntityLevel.Info, score.Level);
        Assert.Equal(GlobalVerdict.Limpio, snap.Verdict);
    }

    [Fact]
    public void Fake_svchost_in_appdata_with_persistence_is_Peligroso()
    {
        var s = new ScanSnapshot();
        var b = Bin(Path.Combine(AppData, "svchost.exe"), false);
        s.Binaries[b.Key] = b;
        s.Processes.Add(new ProcessInfo { Pid = 300, ParentPid = 1, Name = "svchost.exe", Path = b.Path, BinaryKey = b.Key });
        s.Persistence.Add(new PersistenceItem { Type = PersistenceType.RunKey, Location = @"HKU\test\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Name = "svc", Command = b.Path, ResolvedPath = b.Path, BinaryKey = b.Key });

        var (snap, _) = Analyze(s);
        var score = snap.Scores.Single(x => x.ScoringKey == b.Key);
        // H-03 (10) + H-04 (15) + H-05 (50) + H-08 (20) = 95, con bonus de acumulación (≥3 categorías) = 114
        Assert.Contains(snap.Findings, f => f.HeuristicId == "H-05");
        Assert.Contains(snap.Findings, f => f.HeuristicId == "H-08");
        Assert.True(score.AccumulationBonus);
        Assert.Equal(EntityLevel.Peligroso, score.Level);
        Assert.Equal(GlobalVerdict.ProbableInfeccion, snap.Verdict);
        Assert.Contains("se hace pasar por un proceso de Windows", score.WhatWeFound);
        Assert.Contains("disable_startup", score.AvailableActions);
    }

    [Fact]
    public void Known_malicious_hash_is_critical_override()
    {
        var feeds = new FeedStore(NullLogger.Instance);
        var s = new ScanSnapshot();
        var b = Bin(@"C:\Program Files\Signed\app.exe", true, "Some Vendor");
        b.Reputation.Add(new ReputationInfo { Source = "MalwareBazaar", Verdict = "malicious", Family = "RedLine" });
        s.Binaries[b.Key] = b;
        s.Processes.Add(new ProcessInfo { Pid = 400, Name = "app.exe", Path = b.Path, BinaryKey = b.Key });
        var (snap, _) = Analyze(s, feeds);
        var score = snap.Scores.Single(x => x.ScoringKey == b.Key);
        Assert.True(score.CriticalOverride);
        Assert.Equal(EntityLevel.Peligroso, score.Level);
        Assert.Contains("RedLine", score.WhyItCaughtOurAttention[0]);
    }

    [Fact]
    public void Hard_allowlist_ignores_H03_H04_but_not_H01()
    {
        var s = new ScanSnapshot();
        // OneDrive vive en AppData y está firmado por Microsoft: no debe sumar.
        var b = Bin(@"C:\Users\test\AppData\Local\Microsoft\OneDrive\OneDrive.exe", true, "Microsoft Corporation");
        s.Binaries[b.Key] = b;
        s.Processes.Add(new ProcessInfo { Pid = 500, Name = "OneDrive.exe", Path = b.Path, BinaryKey = b.Key });
        var (snap, _) = Analyze(s);
        Assert.All(snap.Findings.Where(f => f.HeuristicId == "H-04"), f => Assert.Equal(0, f.Weight));
        Assert.Equal(GlobalVerdict.Limpio, snap.Verdict);
    }

    [Fact]
    public void Office_spawning_encoded_powershell_triggers_H06_and_H07()
    {
        var s = new ScanSnapshot();
        var word = Bin(@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", true, "Microsoft Corporation");
        var ps = Bin(Path.Combine(Win, @"System32\WindowsPowerShell\v1.0\powershell.exe"), true, "Microsoft Windows");
        s.Binaries[word.Key] = word;
        s.Binaries[ps.Key] = ps;
        var t0 = DateTimeOffset.Now.AddMinutes(-5);
        s.Processes.Add(new ProcessInfo { Pid = 10, Name = "WINWORD.EXE", Path = word.Path, BinaryKey = word.Key, StartTime = t0 });
        s.Processes.Add(new ProcessInfo
        {
            Pid = 11, ParentPid = 10, Name = "powershell.exe", Path = ps.Path, BinaryKey = ps.Key, StartTime = t0.AddMinutes(1),
            CommandLine = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        });
        var (snap, _) = Analyze(s);
        Assert.Contains(snap.Findings, f => f.HeuristicId == "H-06");
        Assert.Contains(snap.Findings, f => f.HeuristicId == "H-07");
        // Las señales del LOLBin se cuelgan del proceso, no del binario compartido powershell.exe.
        var procScore = snap.Scores.Single(x => x.ScoringKey == s.Processes[1].Key);
        Assert.Equal(75, procScore.Score);
        Assert.Equal(EntityLevel.Peligroso, procScore.Level);
    }

    [Fact]
    public void Remote_tool_question_weights_follow_user_answer()
    {
        ScanSnapshot Build()
        {
            var s = new ScanSnapshot();
            s.Software.Add(new InstalledSoftware { Name = "AnyDesk", Publisher = "AnyDesk Software GmbH" });
            return s;
        }

        var (noAnswer, _) = Analyze(Build());
        var card = noAnswer.Scores.Single();
        Assert.Equal(0, card.Score);
        Assert.NotNull(card.PendingQuestion);
        Assert.Equal(GlobalVerdict.Limpio, noAnswer.Verdict);

        var key = Build().Software[0].Key;
        var (phone, _) = Analyze(Build(), answers: new() { [$"{key}|remote_tool_installed_by"] = new UserAnswer { EntityKey = key, QuestionId = "remote_tool_installed_by", Answer = "phone" } });
        Assert.Equal(70, phone.Scores.Single().Score);
        Assert.Equal(GlobalVerdict.ProbableInfeccion, phone.Verdict);

        var (unknown, _) = Analyze(Build(), answers: new() { [$"{key}|remote_tool_installed_by"] = new UserAnswer { EntityKey = key, QuestionId = "remote_tool_installed_by", Answer = "unknown" } });
        Assert.Equal(40, unknown.Scores.Single().Score);
        Assert.Equal(GlobalVerdict.Revisar, unknown.Verdict);
    }

    [Fact]
    public void Ioc_connection_triggers_H02()
    {
        var feeds = new FeedStore(NullLogger.Instance);
        feeds.Ips["185.100.65.9"] = new IocInfo("Feodo Tracker", "servidor de control de botnet", "QakBot", null);
        var s = new ScanSnapshot();
        var b = Bin(@"C:\Users\test\AppData\Local\Temp\x.exe", false);
        s.Binaries[b.Key] = b;
        s.Processes.Add(new ProcessInfo { Pid = 77, Name = "x.exe", Path = b.Path, BinaryKey = b.Key });
        s.Connections.Add(new ConnectionInfo { Pid = 77, RemoteAddress = "185.100.65.9", RemotePort = 443, State = "Established", ProcessName = "x.exe", ProcessPath = b.Path });
        var (snap, _) = Analyze(s, feeds);
        Assert.Contains(snap.Findings, f => f.HeuristicId == "H-02" && f.ScoringKey == b.Key);
        Assert.Equal(EntityLevel.Peligroso, snap.Scores.Single(x => x.ScoringKey == b.Key).Level);
    }

    [Fact]
    public void Defender_exclusion_on_user_folder_triggers_H11()
    {
        var s = new ScanSnapshot();
        s.Settings.Add(new SystemSetting { Name = "defender_exclusion_path", Value = @"C:\Users\test\AppData\Roaming\Microsoft", Category = "infection" });
        s.Settings.Add(new SystemSetting { Name = "defender_exclusion_path", Value = @"D:\Juegos\Steam", Category = "infection" });
        var (snap, _) = Analyze(s);
        Assert.Single(snap.Findings, f => f.HeuristicId == "H-11");
    }

    [Fact]
    public void Hosts_redirecting_bank_triggers_H15()
    {
        var s = new ScanSnapshot();
        s.Settings.Add(new SystemSetting { Name = "hosts", Value = "45.9.20.10 www.bancogalicia.com.ar", Category = "infection" });
        s.Settings.Add(new SystemSetting { Name = "hosts", Value = "127.0.0.1 localhost.dev", Category = "infection" });
        var (snap, _) = Analyze(s);
        var f = Assert.Single(snap.Findings, f => f.HeuristicId == "H-15");
        Assert.Contains("galicia", f.Explanation);
    }

    [Fact]
    public void Persistent_unsigned_connection_across_close_scans_triggers_H25()
    {
        ScanSnapshot Snap(DateTimeOffset when, bool signed)
        {
            var s = new ScanSnapshot { Scan = new ScanInfo { Started = when } };
            var b = Bin(@"C:\Users\test\AppData\Roaming\upd\agent.exe", signed, signed ? "Vendor" : null, sha: "aa11");
            s.Binaries[b.Key] = b;
            s.Processes.Add(new ProcessInfo { Pid = 50, Name = "agent.exe", Path = b.Path, BinaryKey = b.Key });
            s.Connections.Add(new ConnectionInfo { Pid = 50, RemoteAddress = "203.0.113.50", RemotePort = 8443, State = "Established", ProcessName = "agent.exe", ProcessPath = b.Path });
            return s;
        }

        var now = DateTimeOffset.Now;
        foreach (var (gapMinutes, signed, expected) in new[] { (90, false, true), (5, false, false), (90, true, false), (60 * 72, false, false) })
        {
            var current = Snap(now, signed);
            var ctx = new RuleContext { Snapshot = current, Previous = Snap(now.AddMinutes(-gapMinutes), signed), Rules = RuleSet.Load(), Kb = KnowledgeBase.Load(), Feeds = new FeedStore(NullLogger.Instance) };
            var findings = new RulesEngine(NullLogger.Instance).Evaluate(ctx);
            Assert.Equal(expected, findings.Any(f => f.HeuristicId == "H-25"));
        }
    }

    [Fact]
    public void Health_is_separate_from_infection_verdict()
    {
        var s = new ScanSnapshot();
        s.Settings.Add(new SystemSetting { Name = "firewall_public", Value = "0", Ok = false, Category = "health" });
        var (snap, _) = Analyze(s);
        Assert.Equal(GlobalVerdict.Limpio, snap.Verdict);
        Assert.Equal("mejorable", snap.Health.Level);
        Assert.Contains("firewall", snap.Health.Summary);
    }
}
