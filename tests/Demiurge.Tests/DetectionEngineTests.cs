using Demiurge.Core.External;
using Demiurge.Core.Intel;
using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Rules;
using Demiurge.Core.Scoring;
using Demiurge.Core.Text;
using Microsoft.Extensions.Logging.Abstractions;

namespace Demiurge.Tests;

/// <summary>Motores de detección: YARA-X, Microsoft Defender y su historial.</summary>
public class DetectionEngineTests
{
    [Fact]
    public void YaraX_real_output_format_with_meta_is_parsed()
    {
        // Formato real de yr 1.21 (verificado contra el binario): "meta" en vez de "metadata".
        var output = """
            {"path":"C:\\x\\agent.exe","rules":[{"identifier":"CAPE_Asyncrat","meta":[["description","Detects AsyncRAT payload"],["author","kevoreilly"],["score",80]]}]}
            """;
        var d = Assert.Single(YaraXScanner.ParseNdjson(output, ""));
        Assert.Equal("AsyncRAT payload", d.Family);
        Assert.Equal("80", d.Level);
        Assert.Equal("kevoreilly", d.Data["author"]);
    }

    [Theory]
    [InlineData("Detects RedLine Stealer", "X", "RedLine Stealer")]
    [InlineData(null, "MAL_Lumma_Loader", "MAL_Lumma_Loader")]
    public void YaraX_family_from_description(string? description, string rule, string expected) =>
        Assert.Equal(expected, YaraXScanner.FamilyFrom(description, rule));

    [Fact]
    public void Defender_output_with_threat_is_parsed()
    {
        var output = """
            Scan starting...
            Scan finished.
            Scanning C:\x\crack.exe found 1 threats.

            <===========================LIST OF DETECTED THREATS==========================>
            ----------------------------- Threat information ------------------------------
            Threat                  : Trojan:Win32/Wacatac.B!ml
            Resources               : 1 total
                file                : C:\x\crack.exe
            -------------------------------------------------------------------------------
            """;
        var d = Assert.Single(DefenderScanner.Parse(output, 2, @"C:\x\crack.exe"));
        Assert.Equal("DEF", d.Tool);
        Assert.Equal("Trojan:Win32/Wacatac.B!ml", d.Family);
    }

    [Fact]
    public void Defender_clean_output_has_no_detections()
    {
        // Salida real de MpCmdRun sobre un archivo limpio (verificada).
        var output = "Scan starting...\nScan finished.\nScanning C:\\WINDOWS\\System32\\notepad.exe found no threats.\n";
        var d = Assert.Single(DefenderScanner.Parse(output, 0, @"C:\WINDOWS\System32\notepad.exe"));
        Assert.Equal("DEF-OK", d.Tool); // analizado y limpio: se usa para contrastar con YARA
    }

    [Fact]
    public void Defender_resources_are_parsed_into_paths()
    {
        var det = new DefenderDetection { ThreatName = "X", Resources = [@"file:_C:\Users\a\Downloads\x.exe", @"file:_C:\Users\a\Downloads\pack.zip->inner.exe", "regkey:_HKLM\\Software\\X"] };
        Assert.Equal([@"C:\Users\a\Downloads\x.exe", @"C:\Users\a\Downloads\pack.zip"], Heuristics.DefenderFilePaths(det).ToList());
    }

    private static ScanSnapshot Analyze(ScanSnapshot s)
    {
        var rules = RuleSet.Load();
        var kb = KnowledgeBase.Load();
        var ctx = new RuleContext { Snapshot = s, Rules = rules, Kb = kb, Feeds = new FeedStore(NullLogger.Instance) };
        s.Findings = new RulesEngine(NullLogger.Instance).Evaluate(ctx);
        new ScoringEngine(new TextCatalog(), kb).Score(new ScoringEngine.Inputs { Snapshot = s, Rules = rules, Context = ctx });
        return s;
    }

    [Fact]
    public void Defender_confirmation_makes_entity_dangerous_even_if_signed()
    {
        var s = new ScanSnapshot();
        var b = new BinaryInfo { Path = @"C:\Program Files\Tool\tool.exe", Sha256 = "abc", Signature = new SignatureInfo { IsSigned = true, IsValid = true, Signer = "Some Vendor" } };
        s.Binaries[b.Key] = b;
        s.ExternalDetections.Add(new ExternalDetection { Tool = "DEF", Rule = "Trojan:Win32/Wacatac.B!ml", Family = "Trojan:Win32/Wacatac.B!ml", TargetPath = b.Path });
        Analyze(s);
        var score = s.Scores.Single(x => x.ScoringKey == b.Key);
        Assert.Equal(EntityLevel.Peligroso, score.Level);
        Assert.True(score.CriticalOverride);
        Assert.Contains("Microsoft Defender", score.WhyItCaughtOurAttention[0]);
    }

    private static ScanSnapshot YaraCase(string score, bool signed, bool defenderClean, string rule = "MAL_Test")
    {
        var s = new ScanSnapshot();
        var b = new BinaryInfo { Path = @"C:\Program Files\Tool\tool.exe", Sha256 = "abc", Signature = new SignatureInfo { IsSigned = signed, IsValid = signed, Signer = signed ? "Vendor" : null } };
        s.Binaries[b.Key] = b;
        s.ExternalDetections.Add(new ExternalDetection { Tool = "EXT-01", Rule = rule, Family = "F", TargetPath = b.Path, Level = score });
        if (defenderClean) s.ExternalDetections.Add(new ExternalDetection { Tool = "DEF-OK", Rule = "sin amenazas", TargetPath = b.Path });
        return Analyze(s);
    }

    private static int YaraWeight(ScanSnapshot s) => s.Findings.Single(f => f.HeuristicId == "H-26").Weight;

    [Fact]
    public void Yara_weight_depends_on_rule_confidence_and_signature()
    {
        Assert.Equal(60, YaraWeight(YaraCase("85", signed: false, defenderClean: false)));
        Assert.Equal(35, YaraWeight(YaraCase("50", signed: false, defenderClean: false)));
        Assert.Equal(35, YaraWeight(YaraCase("85", signed: true, defenderClean: false)));
        Assert.Equal(35, YaraWeight(YaraCase("85", signed: false, defenderClean: false, rule: "CAPE_Bumblebee")));
    }

    [Fact]
    public void Yara_contradicted_by_defender_lowers_alarm_and_says_so()
    {
        // Caso real de calibración: CAPE_Bumblebee sobre Spotify.dll (firmado), Defender lo dio por limpio.
        var s = YaraCase("80", signed: true, defenderClean: true, rule: "CAPE_Bumblebee");
        var f = s.Findings.Single(x => x.HeuristicId == "H-26");
        Assert.Equal(10, f.Weight);
        Assert.Contains("falso positivo", f.Explanation);
        Assert.Equal(EntityLevel.Info, s.Scores.Single().Level);
        Assert.Equal(GlobalVerdict.Limpio, s.Verdict);

        Assert.Equal(25, YaraWeight(YaraCase("80", signed: false, defenderClean: true)));
    }

    [Fact]
    public void Defender_history_only_flags_files_still_present()
    {
        var present = Path.GetTempFileName();
        try
        {
            var s = new ScanSnapshot();
            s.Defender.Detections.Add(new DefenderDetection { ThreatName = "Trojan:Win32/Present", Time = DateTimeOffset.Now.AddDays(-2), Resources = ["file:_" + present] });
            s.Defender.Detections.Add(new DefenderDetection { ThreatName = "Trojan:Win32/Removed", Time = DateTimeOffset.Now.AddDays(-2), Resources = [@"file:_C:\no\existe\malo.exe"] });
            Analyze(s);
            var f = Assert.Single(s.Findings, x => x.HeuristicId == "H-33");
            Assert.Contains("Trojan:Win32/Present", f.Explanation);
        }
        finally
        {
            File.Delete(present);
        }
    }
}
