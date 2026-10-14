using Demiurge.Core.Collectors;
using Demiurge.Core.External;
using Demiurge.Core.Intel;
using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Rules;
using Demiurge.Core.Scoring;
using Demiurge.Core.Text;
using Microsoft.Extensions.Logging.Abstractions;

namespace Demiurge.Tests;

/// <summary>Historial de ejecución, inicios de sesión, firewall y Hayabusa.</summary>
public class HistoryLogonFirewallTests
{
    private static ScanSnapshot Analyze(ScanSnapshot s, Dictionary<string, UserAnswer>? answers = null)
    {
        var rules = RuleSet.Load();
        var kb = KnowledgeBase.Load();
        var ctx = new RuleContext { Snapshot = s, Rules = rules, Kb = kb, Feeds = new FeedStore(NullLogger.Instance), Answers = answers ?? new() };
        s.Findings = new RulesEngine(NullLogger.Instance).Evaluate(ctx);
        new ScoringEngine(new TextCatalog(), kb).Score(new ScoringEngine.Inputs { Snapshot = s, Rules = rules, Context = ctx });
        return s;
    }

    [Fact]
    public void UserAssist_rot13_is_decoded()
    {
        Assert.Equal(@"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe", ExecutionHistoryCollector.Rot13(@"{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\pzq.rkr"));
    }

    [Fact]
    public void Self_deleted_execution_from_appdata_is_flagged_but_installers_weigh_less()
    {
        var s = new ScanSnapshot();
        s.Executions.Add(new ExecutionRecord { Path = @"C:\Users\a\AppData\Roaming\svc\helper.exe", Name = "helper.exe", Exists = false, LastRun = DateTimeOffset.Now.AddDays(-1), Sources = ["BAM"] });
        s.Executions.Add(new ExecutionRecord { Path = @"C:\Users\a\AppData\Local\Temp\is-AB12C.tmp\setup.tmp", Name = "setup.tmp", Exists = false, LastRun = DateTimeOffset.Now.AddDays(-1), Sources = ["BAM"] });
        s.Executions.Add(new ExecutionRecord { Path = @"C:\Users\a\AppData\Roaming\old\viejo.exe", Name = "viejo.exe", Exists = false, LastRun = DateTimeOffset.Now.AddDays(-40), Sources = ["BAM"] });
        Analyze(s);
        var h34 = s.Findings.Where(f => f.HeuristicId == "H-34").ToList();
        Assert.Equal(2, h34.Count);
        Assert.Equal(30, h34.Single(f => f.EntityName == "helper.exe").Weight);
        Assert.Equal(10, h34.Single(f => f.EntityName == "setup.tmp").Weight);
    }

    [Fact]
    public void Executed_double_extension_document_is_flagged()
    {
        var s = new ScanSnapshot();
        s.Executions.Add(new ExecutionRecord { Path = @"C:\Users\a\Downloads\factura.pdf.exe", Name = "factura.pdf.exe", Exists = true, LastRun = DateTimeOffset.Now.AddHours(-3), Sources = ["UserAssist"] });
        Analyze(s);
        var f = Assert.Single(s.Findings, x => x.HeuristicId == "H-21");
        Assert.Contains("se ejecutó", f.Explanation);
    }

    private static EventInfo Logon(int id, string user, string ip, DateTimeOffset when, string type = "10") => new()
    {
        Log = "Security", EventId = id, Timestamp = when, RecordId = Random.Shared.NextInt64(),
        Data = { ["TargetUserName"] = user, ["IpAddress"] = ip, ["LogonType"] = type },
    };

    [Fact]
    public void Remote_desktop_logon_asks_the_user()
    {
        ScanSnapshot Build()
        {
            var s = new ScanSnapshot();
            s.Events.Add(Logon(4624, "lucia", "45.12.3.4", DateTimeOffset.Now.AddHours(-5)));
            return s;
        }
        var noAnswer = Analyze(Build());
        var card = noAnswer.Scores.Single();
        Assert.NotNull(card.PendingQuestion);
        Assert.Equal(0, card.Score);

        var key = "logon:rdp:lucia|45.12.3.4";
        var no = Analyze(Build(), new() { [$"{key}|remote_logon_known"] = new UserAnswer { EntityKey = key, QuestionId = "remote_logon_known", Answer = "no" } });
        Assert.Equal(80, no.Scores.Single().Score);
        Assert.Equal(GlobalVerdict.ProbableInfeccion, no.Verdict);
    }

    [Fact]
    public void Many_remote_failed_logons_in_24h_is_password_guessing()
    {
        var s = new ScanSnapshot();
        var t0 = DateTimeOffset.Now.AddHours(-10);
        for (int i = 0; i < 25; i++) s.Events.Add(Logon(4625, i % 2 == 0 ? "administrator" : "admin", "185.220.1.9", t0.AddMinutes(i), "3"));
        // Pocos fallos locales (un PIN mal tipeado) no deberían contar.
        for (int i = 0; i < 3; i++) s.Events.Add(Logon(4625, "lucia", "-", t0.AddMinutes(i), "2"));
        Analyze(s);
        var f = Assert.Single(s.Findings, x => x.HeuristicId == "H-36");
        Assert.Equal(45, f.Weight);
        Assert.Contains("185.220.1.9", f.Explanation);
    }

    [Fact]
    public void Firewall_rule_string_is_parsed()
    {
        var r = FirewallCollector.Parse("{ABC}", @"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|App=C:\Users\a\AppData\Roaming\x\rat.exe|Name=Windows Update Helper|", "local");
        Assert.Equal("Allow", r.Action);
        Assert.Equal("In", r.Direction);
        Assert.True(r.Active);
        Assert.Equal("4444", r.LocalPorts);
        Assert.False(r.BuiltIn);
        var builtIn = FirewallCollector.Parse("CoreNet", "v2.30|Action=Allow|Active=TRUE|Dir=In|Name=@FirewallAPI.dll,-25326|EmbedCtxt=@FirewallAPI.dll,-25000|", "local");
        Assert.True(builtIn.BuiltIn);
    }

    [Fact]
    public void Firewall_rule_allowing_unsigned_program_in_is_flagged()
    {
        var s = new ScanSnapshot();
        var b = new BinaryInfo { Path = @"C:\Users\a\AppData\Roaming\x\rat.exe", Sha256 = "f00", Signature = new SignatureInfo { IsSigned = false } };
        s.Binaries[b.Key] = b;
        s.FirewallRules.Add(new FirewallRule { Id = "1", Name = "Windows Update Helper", Action = "Allow", Direction = "In", Active = true, App = b.Path, LocalPorts = "4444", BinaryKey = b.Key });
        Analyze(s);
        Assert.Contains(s.Findings, f => f.HeuristicId == "H-37");
        // Sin firma + carpeta de usuario + regla de firewall: tres categorías distintas sobre el mismo binario.
        Assert.Equal(EntityLevel.Revisar, s.Scores.Single(x => x.ScoringKey == b.Key).Level);
    }

    [Fact]
    public void Hayabusa_v4_jsonl_is_parsed_and_grouped_by_rule()
    {
        var lines = new[]
        {
            """{ "Timestamp":"2026-10-14T10:00:00Z","RuleTitle":"Mimikatz Use","Level":"crit","Computer":"pc","Channel":"Sec","EventID":4688,"RecordID":1,"Details":{"Cmdline":"x"},"RuleID":"a"}""",
            """{ "Timestamp":"2026-10-14T11:00:00Z","RuleTitle":"Mimikatz Use","Level":"crit","Computer":"pc","Channel":"Sec","EventID":4688,"RecordID":2,"Details":{"Cmdline":"y"},"RuleID":"a"}""",
            """{ "Timestamp":"2026-10-14T09:00:00Z","RuleTitle":"Log Cleared","Level":"emer","Computer":"pc","Channel":"Sec","EventID":1102,"RecordID":3,"Details":{},"RuleID":"b"}""",
        };
        var dets = HayabusaScanner.Parse(lines);
        Assert.Equal(2, dets.Count);
        var mimi = dets.Single(d => d.Rule == "Mimikatz Use");
        Assert.Equal("critical", mimi.Level);
        Assert.Equal("2", mimi.Data["count"]);
        Assert.Equal("2026-10-14T11:00:00Z", mimi.Data["last"]);
        Assert.Equal("critical", dets.Single(d => d.Rule == "Log Cleared").Level); // "emer" (v4) se trata como crítico
    }
}
