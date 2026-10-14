using Demiurge.Core.External;
using Demiurge.Core.Intel;
using Demiurge.Core.Knowledge;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Tests;

public class ParsingTests
{
    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --minimized", "C:\\Program Files\\App\\app.exe", "--minimized")]
    [InlineData("C:\\Windows\\System32\\cmd.exe /c start", "C:\\Windows\\System32\\cmd.exe", "/c start")]
    public void CommandLineResolver_splits_executable_and_args(string cmd, string exe, string args)
    {
        var r = CommandLineResolver.Resolve(cmd);
        Assert.Equal(exe, r.Executable, ignoreCase: true);
        Assert.Equal(args, r.Arguments);
    }

    [Fact]
    public void CommandLineResolver_resolves_rundll32_hosted_module()
    {
        var r = CommandLineResolver.Resolve("rundll32.exe \"C:\\Users\\x\\AppData\\Roaming\\evil.dll\",Start");
        Assert.EndsWith("rundll32.exe", r.Executable, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("C:\\Users\\x\\AppData\\Roaming\\evil.dll", r.HostedModule);
    }

    [Theory]
    [InlineData("factura.pdf.exe", true)]
    [InlineData("foto.jpg.scr", true)]
    [InlineData("documento          .exe", true)]
    [InlineData("setup.exe", false)]
    [InlineData("informe.pdf", false)]
    public void Double_extension_detection(string name, bool expected) =>
        Assert.Equal(expected, PathClassifier.HasDoubleExtension(name));

    [Theory]
    [InlineData(@"C:\Users\a\AppData\Roaming\x.exe", "AppData\\Roaming")]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\x.exe", "Temp")]
    [InlineData(@"C:\Users\Public\x.exe", "Users\\Public")]
    [InlineData(@"C:\Program Files\x\x.exe", null)]
    public void User_folder_classification(string path, string? expected) =>
        Assert.Equal(expected, PathClassifier.UserWritableFolder(path));

    [Fact]
    public void ThreatFox_csv_is_parsed_into_indexes()
    {
        var file = Path.GetTempFileName();
        File.WriteAllLines(file,
        [
            "# ThreatFox IOCs: CSV export",
            "\"2026-10-01 10:00:00\", \"1\", \"185.1.2.3:8080\", \"ip:port\", \"botnet_cc\", \"win.redline\", \"None\", \"RedLine Stealer\", \"\", \"100\", \"\", \"\", \"0\", \"x\"",
            "\"2026-10-01 10:00:00\", \"2\", \"evil-c2.example\", \"domain\", \"botnet_cc\", \"win.lumma\", \"None\", \"Lumma Stealer\", \"\", \"100\", \"\", \"\", \"0\", \"x\"",
            "\"2026-10-01 10:00:00\", \"3\", \"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\", \"sha256_hash\", \"payload\", \"win.lumma\", \"None\", \"Lumma Stealer\", \"\", \"100\", \"\", \"\", \"0\", \"x\"",
        ]);
        var ips = new Dictionary<string, IocInfo>(); var ipPorts = new Dictionary<string, IocInfo>();
        var domains = new Dictionary<string, IocInfo>(); var hashes = new Dictionary<string, IocInfo>();
        FeedStore.LoadThreatFox(file, ips, ipPorts, domains, hashes);
        File.Delete(file);
        Assert.Equal("RedLine Stealer", ips["185.1.2.3"].Family);
        Assert.True(ipPorts.ContainsKey("185.1.2.3:8080"));
        Assert.True(domains.ContainsKey("evil-c2.example"));
        Assert.Single(hashes);
    }

    [Fact]
    public void Urlhaus_shared_hosts_match_only_by_exact_url()
    {
        var file = Path.GetTempFileName();
        File.WriteAllLines(file,
        [
            "# URLhaus",
            "\"1\",\"2026-10-01\",\"https://files.pythonhosted.org/packages/xx/evil-1.0.tar.gz\",\"online\",\"\",\"malware_download\",\"None\",\"https://urlhaus.abuse.ch/url/1/\",\"x\"",
            "\"2\",\"2026-10-01\",\"http://bad-dropper.example/payload.exe\",\"online\",\"\",\"malware_download\",\"AsyncRAT\",\"https://urlhaus.abuse.ch/url/2/\",\"x\"",
        ]);
        var domains = new Dictionary<string, IocInfo>(StringComparer.OrdinalIgnoreCase);
        var urls = new Dictionary<string, IocInfo>(StringComparer.OrdinalIgnoreCase);
        FeedStore.LoadUrlhaus(file, domains, urls);
        File.Delete(file);
        // Regresión: files.pythonhosted.org salía "Peligroso" en una PC limpia por matchear el dominio compartido.
        Assert.False(domains.ContainsKey("files.pythonhosted.org"));
        Assert.True(FeedStore.IsSharedHost("cdn.jsdelivr.net")); // regresión: salía "Peligroso" en una PC limpia
        Assert.True(domains.ContainsKey("bad-dropper.example"));
        Assert.True(urls.ContainsKey("https://files.pythonhosted.org/packages/xx/evil-1.0.tar.gz"));
    }

    [Fact]
    public void Domain_match_walks_parent_domains()
    {
        var store = new FeedStore(Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        store.Domains["evil.example"] = new IocInfo("URLhaus", "distribución de malware", null, null);
        Assert.NotNull(store.MatchDomain("cdn.a.evil.example"));
        Assert.Null(store.MatchDomain("example"));
        Assert.Null(store.MatchDomain("good.example"));
    }

    [Fact]
    public void KnowledgeBase_trusts_only_matching_signer_and_location()
    {
        var kb = KnowledgeBase.Load();
        Assert.True(kb.Entries.Count >= 150);
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var real = new BinaryInfo { Path = Path.Combine(win, "System32", "svchost.exe"), Signature = new SignatureInfo { IsSigned = true, IsValid = true, Signer = "Microsoft Windows Publisher" } };
        var fake = new BinaryInfo { Path = @"C:\Users\x\AppData\Roaming\svchost.exe", Signature = new SignatureInfo { IsSigned = false } };
        Assert.True(kb.MatchBinary(real)!.Trusted);
        var m = kb.MatchBinary(fake)!;
        Assert.False(m.Trusted);
        Assert.True(m.Mismatch);
        Assert.Equal("remote_tool", kb.MatchSoftware(new InstalledSoftware { Name = "TeamViewer 15" })!.Category);
    }

    [Fact]
    public void YaraX_ndjson_output_is_parsed()
    {
        var output = """
            {"path":"C:\\x\\a.exe","rules":[{"identifier":"MAL_RedLine_Stealer","namespace":"default","metadata":[["description","Detects RedLine"],["malware_family","RedLine"]]}]}
            {"path":"C:\\x\\b.exe","rules":[]}
            """;
        var d = Assert.Single(YaraXScanner.ParseNdjson(output, "fallback"));
        Assert.Equal("EXT-01", d.Tool);
        Assert.Equal("RedLine", d.Family);
        Assert.Equal("C:\\x\\a.exe", d.TargetPath);
    }

    [Fact]
    public void HollowsHunter_json_is_parsed_and_noise_filtered()
    {
        var output = """
            {"scan_date_time":"x","suspicious":[
              {"pid":1234,"name":"notepad.exe","replaced":1,"implanted":0,"patched":0},
              {"pid":555,"name":"game.exe","patched":3,"iat_hooked":1}
            ]}
            """;
        var d = Assert.Single(HollowsHunterScanner.Parse(output));
        Assert.Equal(1234, d.Pid);
        Assert.Contains("hollowing", d.Rule);
    }

    [Fact]
    public void Registry_cert_blob_extracts_der()
    {
        var der = new byte[] { 0x30, 0x82, 0x01, 0x02 };
        var blob = new List<byte>();
        void Prop(int id, byte[] data) { blob.AddRange(BitConverter.GetBytes(id)); blob.AddRange(BitConverter.GetBytes(1)); blob.AddRange(BitConverter.GetBytes(data.Length)); blob.AddRange(data); }
        Prop(3, new byte[20]);
        Prop(32, der);
        Assert.Equal(der, Demiurge.Core.Collectors.CertificateCollector.ExtractCertFromBlob(blob.ToArray()));
    }
}
