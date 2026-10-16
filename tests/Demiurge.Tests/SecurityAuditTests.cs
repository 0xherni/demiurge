using System.Diagnostics;
using System.Security;
using Demiurge.Core;
using Demiurge.Core.Actions;
using Demiurge.Core.Enrichment;
using Demiurge.Core.Intel;
using Demiurge.Core.Model;
using Demiurge.Core.Native;
using Demiurge.Core.Security;
using Demiurge.Core.Util;

namespace Demiurge.Tests;

/// <summary>
/// Auditoría de seguridad (octubre 2026): cada test intenta el abuso que la corrección tiene que frenar.
/// </summary>
public class SecurityAuditTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "demiurge-audit-" + Guid.NewGuid().ToString("N"));

    public SecurityAuditTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try
        {
            foreach (var d in Directory.GetFileSystemEntries(_dir))
                if (File.GetAttributes(d).HasFlag(FileAttributes.ReparsePoint)) Directory.Delete(d); // el enlace, no su destino
            Directory.Delete(_dir, true);
        }
        catch { }
    }

    private static void Junction(string link, string target)
    {
        using var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
        p.WaitForExit();
        Assert.True(Directory.Exists(link), "no se pudo crear el junction de prueba");
    }

    // ------------------------------------------------------------ Carpeta de datos

    [Fact]
    public void Elevated_app_ignores_DEMIURGE_HOME()
    {
        var programData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Demiurge");
        Assert.Equal(programData, DemiurgePaths.ResolveRoot(@"C:\Windows", elevated: true));
        Assert.Equal(@"D:\dev\home", DemiurgePaths.ResolveRoot(@"D:\dev\home", elevated: false));
        Assert.Equal(programData, DemiurgePaths.ResolveRoot(null, elevated: false));
    }

    [Fact]
    public void Data_root_planted_as_junction_is_set_aside_without_touching_its_target()
    {
        var victim = Directory.CreateDirectory(Path.Combine(_dir, "victim")).FullName;
        File.WriteAllText(Path.Combine(victim, "important.txt"), "no tocar");
        var root = Path.Combine(_dir, "Demiurge");
        Junction(root, victim);

        var notes = new List<string>();
        var aside = DataDirectoryLockdown.SetAsideIfUnsafe(root, _ => true, notes);

        Assert.NotNull(aside);
        Assert.False(Directory.Exists(root));                                     // el enlace ya no está en su lugar
        Assert.True(File.GetAttributes(aside!).HasFlag(FileAttributes.ReparsePoint)); // se renombró el enlace, no el destino
        Assert.Equal("no tocar", File.ReadAllText(Path.Combine(victim, "important.txt")));
        Assert.Contains(notes, n => n.Contains("enlace"));
    }

    [Fact]
    public void Data_root_created_by_another_user_is_set_aside()
    {
        var root = Directory.CreateDirectory(Path.Combine(_dir, "Demiurge")).FullName;
        var aside = DataDirectoryLockdown.SetAsideIfUnsafe(root, _ => false, new List<string>());
        Assert.NotNull(aside);
        Assert.False(Directory.Exists(root));
        Assert.True(Directory.Exists(aside));
    }

    [Fact]
    public void Trusted_data_root_is_left_alone()
    {
        var root = Directory.CreateDirectory(Path.Combine(_dir, "Demiurge")).FullName;
        Assert.Null(DataDirectoryLockdown.SetAsideIfUnsafe(root, _ => true, new List<string>()));
        Assert.Null(DataDirectoryLockdown.SetAsideIfUnsafe(Path.Combine(_dir, "no-existe"), _ => true, new List<string>()));
    }

    // ------------------------------------------------------------ Firmas

    [Fact]
    public void Real_windows_binary_is_microsoft_by_its_certificate_chain()
    {
        var sig = WinTrust.Verify(Path.Combine(PathClassifier.System32Dir, "notepad.exe"));
        Assert.True(sig.IsValid);
        Assert.True(sig.ChainChecked);
        Assert.NotNull(sig.RootThumbprint);
        Assert.Contains(sig.RootThumbprint!, SignatureInfo.MicrosoftRoots);
        Assert.True(sig.IsMicrosoft);
    }

    [Fact]
    public void Microsoft_name_without_microsoft_root_is_not_microsoft()
    {
        // Lo que vería Demiurge si un malware instala su propio certificado raíz y firma como "Microsoft Corporation".
        var forged = new SignatureInfo { IsSigned = true, IsValid = true, Signer = "Microsoft Corporation", ChainChecked = true, RootThumbprint = "00112233445566778899AABBCCDDEEFF00112233" };
        Assert.False(forged.IsMicrosoft);
        var noChain = new SignatureInfo { IsSigned = true, IsValid = true, Signer = "Microsoft Windows", ChainChecked = true, RootThumbprint = null };
        Assert.False(noChain.IsMicrosoft);
        var real = new SignatureInfo { IsSigned = true, IsValid = true, Signer = "Microsoft Windows", ChainChecked = true, RootThumbprint = "3B1EFD3A66EA28B16697394703A72CA340A05BD5" };
        Assert.True(real.IsMicrosoft);
    }

    [Fact]
    public void Fake_WindowsApps_folder_outside_program_files_is_not_a_package()
    {
        Assert.Null(WinTrust.PackageRoot(@"C:\Users\x\AppData\Local\Temp\WindowsApps\Evil_1.0_x64__8wekyb3d8bbwe\evil.exe"));
        Assert.Null(WinTrust.PackageRoot(@"C:\Users\x\Desktop\SystemApps\Fake_cw5n1h2txyewy\a.exe"));
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var real = Path.Combine(programFiles, "WindowsApps", "App_1.0_x64__abc", "app.exe");
        Assert.Equal(Path.Combine(programFiles, "WindowsApps", "App_1.0_x64__abc"), WinTrust.PackageRoot(real));
        // Rutas con ".." que salen de la carpeta protegida tampoco valen.
        Assert.Null(WinTrust.PackageRoot(Path.Combine(programFiles, "WindowsApps", "..", "..", "Users", "x", "evil.exe")));
    }

    [Fact]
    public void Signature_from_a_root_added_on_this_pc_does_not_count_as_valid()
    {
        var s = new ScanSnapshot();
        var local = new BinaryInfo { Path = @"C:\Users\a\AppData\Roaming\x\x.exe", Sha256 = "1", Signature = new SignatureInfo { IsSigned = true, IsValid = true, Signer = "Microsoft Corporation", ChainChecked = true, RootThumbprint = "AAAA" } };
        var pub = new BinaryInfo { Path = @"C:\Program Files\App\app.exe", Sha256 = "2", Signature = new SignatureInfo { IsSigned = true, IsValid = true, Signer = "App Inc.", ChainChecked = true, RootThumbprint = "BBBB" } };
        s.Binaries[local.Key] = local;
        s.Binaries[pub.Key] = pub;

        ScanOrchestrator.DistrustLocalRoots(s, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "BBBB" });
        Assert.False(local.Signature!.IsValid);
        Assert.Contains("raíz", local.Signature.Error);
        Assert.True(pub.Signature!.IsValid);

        // Sin la lista de raíces públicas (todavía sin internet) no se decide nada.
        local.Signature.IsValid = true;
        ScanOrchestrator.DistrustLocalRoots(s, new HashSet<string>());
        Assert.True(local.Signature.IsValid);
    }

    [Fact]
    public void Circl_known_malicious_is_never_benign()
    {
        var bad = ReputationService.ParseCircl("""{"FileName":"x.exe","KnownMalicious":"malshare.com","ProductName":"x"}""");
        Assert.NotEqual("benign", bad.Verdict);
        var good = ReputationService.ParseCircl("""{"FileName":"notepad.exe","ProductName":"Windows"}""");
        Assert.Equal("benign", good.Verdict);
    }

    // ------------------------------------------------------------ Acciones

    [Fact]
    public void Critical_windows_processes_are_never_killed_but_impostors_are()
    {
        var s = new ScanSnapshot();
        var sys = PathClassifier.System32Dir;
        Assert.True(ActionService.IsProtectedProcess(new ProcessInfo { Pid = 700, Name = "lsass.exe", Path = Path.Combine(sys, "lsass.exe") }, s));
        Assert.True(ActionService.IsProtectedProcess(new ProcessInfo { Pid = 4, Name = "System" }, s));
        Assert.True(ActionService.IsProtectedProcess(new ProcessInfo { Pid = Environment.ProcessId, Name = "x.exe", Path = @"C:\x.exe" }, s));
        // Un "svchost.exe" fuera de Windows es justamente lo sospechoso: ése sí se puede finalizar.
        Assert.False(ActionService.IsProtectedProcess(new ProcessInfo { Pid = 9388, Name = "svchost.exe", Path = @"C:\Users\a\AppData\Roaming\Microsoft\svchost.exe" }, s));
    }

    [Fact]
    public void Restore_into_a_folder_replaced_by_a_junction_is_refused()
    {
        var victim = Directory.CreateDirectory(Path.Combine(_dir, "victim")).FullName;
        var userDir = Path.Combine(_dir, "user");
        Junction(userDir, victim);
        var backup = Path.Combine(_dir, "backup.bin");
        File.WriteAllText(backup, "payload");

        Assert.ThrowsAny<SecurityException>(() => SafeFile.RestoreTo(backup, Path.Combine(userDir, "restored.dll")));
        Assert.False(File.Exists(Path.Combine(victim, "restored.dll")));
    }

    [Fact]
    public void Restore_creates_the_file_inside_the_real_folder()
    {
        var userDir = Directory.CreateDirectory(Path.Combine(_dir, "user")).FullName;
        var backup = Path.Combine(_dir, "backup.bin");
        File.WriteAllText(backup, "contenido");
        SafeFile.RestoreTo(backup, Path.Combine(userDir, "restored.txt"));
        Assert.Equal("contenido", File.ReadAllText(Path.Combine(userDir, "restored.txt")));
    }

    [Fact]
    public void Folder_restore_goes_back_to_its_place_and_refuses_junctions()
    {
        var parent = Directory.CreateDirectory(Path.Combine(_dir, "profile")).FullName;
        var backupDir = Directory.CreateDirectory(Path.Combine(_dir, "backups", "ext1")).FullName;
        File.WriteAllText(Path.Combine(backupDir, "manifest.json"), "{}");

        SafeFile.RestoreDirectory(backupDir, Path.Combine(parent, "ext1"));
        Assert.True(File.Exists(Path.Combine(parent, "ext1", "manifest.json")));
        Assert.False(Directory.Exists(backupDir));

        var victim = Directory.CreateDirectory(Path.Combine(_dir, "victim")).FullName;
        var linked = Path.Combine(_dir, "linked");
        Junction(linked, victim);
        var backup2 = Directory.CreateDirectory(Path.Combine(_dir, "backups", "ext2")).FullName;
        Assert.ThrowsAny<SecurityException>(() => SafeFile.RestoreDirectory(backup2, Path.Combine(linked, "ext2")));
        Assert.False(Directory.Exists(Path.Combine(victim, "ext2")));
    }

    // ------------------------------------------------------------ Descargas

    [Fact]
    public async Task Oversized_download_is_cut_off()
    {
        using var big = new MemoryStream(new byte[3 * 1024 * 1024]);
        using var sink = new MemoryStream();
        await Assert.ThrowsAsync<InvalidDataException>(() => FeedUpdater.CopyLimitedAsync(big, sink, 1024 * 1024, CancellationToken.None));
        Assert.True(sink.Length <= 1024 * 1024);
    }
}
