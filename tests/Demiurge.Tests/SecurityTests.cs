using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.Json.Nodes;
using Demiurge.Core;
using Demiurge.Core.Ipc;
using Demiurge.Core.Native;
using Microsoft.Extensions.Logging.Abstractions;

namespace Demiurge.Tests;

/// <summary>Intenta los ataques que el blindaje tiene que frenar.</summary>
public class SecurityTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "demiurge-sec-" + Guid.NewGuid().ToString("N"));

    public SecurityTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try
        {
            foreach (var d in Directory.GetDirectories(_dir))
                if (new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.ReparsePoint)) Directory.Delete(d); // borrar el junction, no el destino
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLinkW(string link, string existing, IntPtr sa);

    [Fact]
    public void SafeFile_reads_normal_file()
    {
        var f = Path.Combine(_dir, "Preferences");
        File.WriteAllText(f, "{\"a\":1}");
        Assert.Equal("{\"a\":1}", SafeFile.ReadAllText(f));
    }

    [Fact]
    public void SafeFile_rejects_path_redirected_through_junction()
    {
        // Simula: el usuario cambia la carpeta de su perfil por un junction a otra carpeta (p.ej. C:\Windows).
        var real = Path.Combine(_dir, "sistema");
        Directory.CreateDirectory(real);
        File.WriteAllText(Path.Combine(real, "Preferences"), "importante");
        var link = Path.Combine(_dir, "perfil");
        Junction(link, real);

        Assert.Throws<SecurityException>(() => SafeFile.WriteAllText(Path.Combine(link, "Preferences"), "pisado"));
        Assert.Throws<SecurityException>(() => SafeFile.MoveOut(Path.Combine(link, "Preferences"), Path.Combine(_dir, "out.bin")));
        Assert.Equal("importante", File.ReadAllText(Path.Combine(real, "Preferences")));
        Assert.False(File.Exists(Path.Combine(_dir, "out.bin")));
    }

    [Fact]
    public void SafeFile_rejects_hardlinks()
    {
        var target = Path.Combine(_dir, "archivo-del-sistema.txt");
        File.WriteAllText(target, "importante");
        var link = Path.Combine(_dir, "Preferences");
        Assert.True(CreateHardLinkW(link, target, IntPtr.Zero));
        Assert.Throws<SecurityException>(() => SafeFile.WriteAllText(link, "pisado"));
        Assert.Equal("importante", File.ReadAllText(target));
    }

    [Fact]
    public void Quarantine_refuses_file_changed_since_scan()
    {
        var f = Path.Combine(_dir, "malware.exe");
        File.WriteAllText(f, "contenido nuevo");
        Assert.Throws<SecurityException>(() => SafeFile.MoveOut(f, Path.Combine(_dir, "q.bin"), expectedSha256: new string('0', 64)));
        Assert.True(File.Exists(f));
    }

    [Fact]
    public void MoveOut_moves_and_deletes_original()
    {
        var f = Path.Combine(_dir, "startup.lnk");
        File.WriteAllBytes(f, [1, 2, 3]);
        var dest = Path.Combine(_dir, "backup.bin");
        SafeFile.MoveOut(f, dest, d => d.Select(b => (byte)(b ^ 0xA5)).ToArray());
        Assert.False(File.Exists(f));
        Assert.Equal(new byte[] { 1 ^ 0xA5, 2 ^ 0xA5, 3 ^ 0xA5 }, File.ReadAllBytes(dest));
    }

    [Fact]
    public void Operation_sets_cover_every_operation_and_actions_are_not_public()
    {
        foreach (var op in Protocol.PublicOperations.Concat(Protocol.ReadOperations))
            Assert.Contains(op, Protocol.Operations);
        foreach (var dangerous in new[] { "action.execute", "action.revert", "answer", "finding.state", "allowlist.remove", "config.set", "tools.pin", "sysmon.install", "scan.cancel", "scan.start" })
        {
            Assert.DoesNotContain(dangerous, Protocol.PublicOperations);
            Assert.DoesNotContain(dangerous, Protocol.ReadOperations);
        }
    }

    [Fact]
    public async Task Unelevated_caller_cannot_execute_actions_or_allowlist()
    {
        var home = Path.Combine(_dir, "home");
        Environment.SetEnvironmentVariable("DEMIURGE_HOME", home);
        Demiurge.Core.Util.DemiurgePaths.Root = home;
        await using var engine = new DemiurgeEngine(NullLogger.Instance);
        var malware = new CallerInfo(1234, "usuario", Elevated: false, @"C:\Users\x\AppData\Local\Temp\evil.exe");

        foreach (var op in new[] { "action.execute", "answer", "config.set", "tools.pin", "scan.start", "inventory" })
        {
            var req = new IpcRequest { Op = op, Args = new JsonObject { ["action"] = "allowlist", ["entityKey"] = "x", ["confirmed"] = true } };
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => engine.HandleAsync(req, malware, CancellationToken.None));
        }

        // El estado sí lo puede ver cualquiera (ícono de la bandeja).
        var ping = await engine.HandleAsync(new IpcRequest { Op = "ping" }, malware, CancellationToken.None);
        Assert.NotNull(ping);
    }
}
