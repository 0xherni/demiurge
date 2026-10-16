using Demiurge.Core.Intel;
using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Rules;
using Demiurge.Core.Scoring;
using Demiurge.Core.Storage;
using Demiurge.Core.Story;
using Demiurge.Core.Text;
using Microsoft.Extensions.Logging.Abstractions;

namespace Demiurge.Tests;

/// <summary>Plan de limpieza guiado y línea de tiempo "Qué pasó".</summary>
public class StoryTests
{
    private static ScanSnapshot Analyze(ScanSnapshot s)
    {
        var rules = RuleSet.Load();
        var kb = KnowledgeBase.Load();
        var ctx = new RuleContext { Snapshot = s, Rules = rules, Kb = kb, Feeds = new FeedStore(NullLogger.Instance) };
        s.Findings = new RulesEngine(NullLogger.Instance).Evaluate(ctx);
        new ScoringEngine(new TextCatalog(), kb).Score(new ScoringEngine.Inputs { Snapshot = s, Rules = rules, Context = ctx });
        return s;
    }

    /// <summary>Un ladrón de contraseñas conocido: se descargó, se ejecutó, sigue corriendo y arranca solo.</summary>
    private static (ScanSnapshot s, BinaryInfo b) Infected()
    {
        var s = new ScanSnapshot { Scan = new ScanInfo { Id = 7, Started = DateTimeOffset.Now.AddMinutes(-5) } };
        var path = @"C:\Users\a\AppData\Roaming\svc\helper.exe";
        var b = new BinaryInfo
        {
            Path = path, Sha256 = "abc", Created = DateTimeOffset.Now.AddHours(-26), Signature = new SignatureInfo { IsSigned = false },
            Reputation = [new ReputationInfo { Source = "MalwareBazaar", Verdict = "malicious", Family = "LummaStealer" }],
        };
        s.Binaries[b.Key] = b;
        s.RecentFiles.Add(new RecentFile { Path = path, Created = DateTimeOffset.Now.AddHours(-26), HostUrl = "https://cdn-verify.top/x.exe", BinaryKey = b.Key });
        s.Executions.Add(new ExecutionRecord { Path = path, Name = "helper.exe", LastRun = DateTimeOffset.Now.AddHours(-25.9), Exists = true, BinaryKey = b.Key, Sources = ["BAM"] });
        s.Processes.Add(new ProcessInfo { Pid = 4321, Name = "helper.exe", Path = path, BinaryKey = b.Key, StartTime = DateTimeOffset.Now.AddHours(-2) });
        s.Persistence.Add(new PersistenceItem { Type = PersistenceType.RunKey, Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", Name = "Helper", Command = path, BinaryKey = b.Key });
        s.Extensions.Add(new BrowserExtension { Browser = "Chrome", Profile = "Default", Id = "x", Name = "Google Docs Offline" });
        s.AppIntegrity.Add(new AppIntegrityInfo { App = "Discord", Path = @"C:\d\index.js", Status = "original" });
        return (Analyze(s), b);
    }

    [Fact]
    public void Clean_pc_has_nothing_to_clean()
    {
        var s = Analyze(new ScanSnapshot());
        var plan = CleanupPlanBuilder.Build(s, [], new TextCatalog());
        Assert.Equal("clean", plan.Status);
        Assert.Empty(plan.Phases);
    }

    [Fact]
    public void Plan_orders_steps_from_stopping_the_damage_to_verifying()
    {
        var (s, _) = Infected();
        var plan = CleanupPlanBuilder.Build(s, [], new TextCatalog());
        Assert.Equal("cleanup", plan.Status);
        var order = plan.Phases.Select(p => p.Id).ToList();
        Assert.Equal(["offline", "stop", "startup", "isolate", "passwords", "verify"], order);
        Assert.Contains(plan.Phases.Single(p => p.Id == "stop").Steps, st => st.Action == "kill_process");
        Assert.Equal("scan", plan.Phases[^1].Steps.Single().Kind);
    }

    [Fact]
    public void Password_step_lists_the_accounts_this_pc_had()
    {
        var (s, _) = Infected();
        var items = CleanupPlanBuilder.Build(s, [], new TextCatalog()).Phases.Single(p => p.Id == "passwords").Steps.Single().Items;
        Assert.StartsWith("Tu mail principal", items[0]);
        Assert.Contains(items, i => i.Contains("Chrome"));
        Assert.Contains("Discord", items);
    }

    [Fact]
    public void A_step_is_done_when_its_action_was_recorded_after_the_scan()
    {
        var (s, b) = Infected();
        var actions = new List<ActionRecord>
        {
            new() { Type = "kill", Target = b.Key, Date = DateTimeOffset.Now },
            // Una acción revertida no cuenta.
            new() { Type = "quarantine", Target = b.Key, Date = DateTimeOffset.Now, Reverted = true },
        };
        var plan = CleanupPlanBuilder.Build(s, actions, new TextCatalog());
        Assert.True(plan.Phases.Single(p => p.Id == "stop").Steps.Single().Done);
        Assert.False(plan.Phases.Single(p => p.Id == "isolate").Steps.Single().Done);
    }

    [Fact]
    public void Review_level_items_are_conditional_and_never_quarantined()
    {
        // Calibración real: el plan proponía poner en cuarentena el servicio de Focusrite (sólo "para revisar").
        var s = new ScanSnapshot();
        var b = new BinaryInfo { Path = @"C:\Users\a\AppData\Local\Tool\tool.exe", Sha256 = "t", Signature = new SignatureInfo { IsSigned = false } };
        s.Binaries[b.Key] = b;
        s.Persistence.Add(new PersistenceItem { Type = PersistenceType.RunKey, Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", Name = "Tool", Command = b.Path, BinaryKey = b.Key });
        Analyze(s);
        Assert.Equal(EntityLevel.Revisar, s.Scores.Single().Level);

        var plan = CleanupPlanBuilder.Build(s, [], new TextCatalog());
        Assert.DoesNotContain(plan.Phases, p => p.Id is "isolate" or "offline");
        var step = plan.Phases.Single(p => p.Id == "startup").Steps.Single();
        Assert.Equal("review", step.Level);
        Assert.StartsWith("Si no reconocés tool.exe", step.Title);
    }

    [Fact]
    public void Timeline_tells_the_story_in_order_and_links_only_the_same_file()
    {
        var (s, b) = Infected();
        var tl = TimelineBuilder.Build(s, []);

        var first = tl.Episodes[^1]; // el más viejo (la lista va del más reciente al más viejo)
        Assert.Equal("Se descargó helper.exe", first.Events[0].Title);
        Assert.Equal("Se ejecutó helper.exe", first.Events[1].Title);
        Assert.Equal(first.Events[0].Thread, first.Events[1].Thread);
        Assert.Contains("cdn-verify.top", first.Events[0].Detail);

        // Lo de hace 2 horas (el proceso abierto) es otro momento: están separados por más de 3 horas.
        Assert.Equal(2, tl.Episodes.Count);
        // El arranque no tiene fecha en Windows: va aparte, sin inventarle una.
        Assert.Contains(tl.Undated, e => e.Kind == "startup" && e.Thread == b.Path.ToLowerInvariant());
    }

    [Fact]
    public void Timeline_ignores_things_that_are_not_suspicious()
    {
        var s = new ScanSnapshot();
        var b = new BinaryInfo { Path = @"C:\Program Files\App\app.exe", Sha256 = "1", Created = DateTimeOffset.Now.AddDays(-1), Signature = new SignatureInfo { IsSigned = true, IsValid = true, Signer = "App Inc." } };
        s.Binaries[b.Key] = b;
        s.Executions.Add(new ExecutionRecord { Path = b.Path, Name = "app.exe", LastRun = DateTimeOffset.Now.AddHours(-1), Exists = true, BinaryKey = b.Key });
        var tl = TimelineBuilder.Build(Analyze(s), []);
        Assert.Empty(tl.Episodes);
        Assert.Empty(tl.Undated);
    }
}
