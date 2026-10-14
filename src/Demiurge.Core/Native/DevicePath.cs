using System.Runtime.InteropServices;
using System.Text;

namespace Demiurge.Core.Native;

/// <summary>Convierte rutas de dispositivo (\Device\HarddiskVolume3\...) a rutas DOS (C:\...).</summary>
internal static class DevicePath
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr h, int cls, IntPtr info, int len, out int retLen);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    private static Dictionary<string, string>? _map;
    private static DateTime _built;

    public static string ToDosPath(string path)
    {
        if (!path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), path[12..]);
            return path.StartsWith(@"\??\") ? path[4..] : path;
        }
        if (_map is null || DateTime.UtcNow - _built > TimeSpan.FromMinutes(5)) Build();
        foreach (var (device, drive) in _map!)
            if (path.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
                return drive + path[device.Length..];
        return path;
    }

    private static void Build()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var drive in Environment.GetLogicalDrives())
        {
            var letter = drive.TrimEnd('\\');
            var sb = new StringBuilder(512);
            if (QueryDosDevice(letter, sb, sb.Capacity) > 0) map[sb.ToString()] = letter;
        }
        _map = map;
        _built = DateTime.UtcNow;
    }

    /// <summary>Línea de comandos de un proceso vivo (ProcessCommandLineInformation, Win 8.1+).</summary>
    public static string? GetCommandLine(int pid)
    {
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            NtQueryInformationProcess(h, 60, IntPtr.Zero, 0, out int len);
            if (len <= 0 || len > 1 << 20) return null;
            IntPtr buf = Marshal.AllocHGlobal(len);
            try
            {
                if (NtQueryInformationProcess(h, 60, buf, len, out _) != 0) return null;
                // UNICODE_STRING { ushort Length; ushort MaxLength; [pad]; PWSTR Buffer }
                ushort strLen = (ushort)Marshal.ReadInt16(buf);
                IntPtr str = Marshal.ReadIntPtr(buf, IntPtr.Size);
                return strLen == 0 ? null : Marshal.PtrToStringUni(str, strLen / 2);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { CloseHandle(h); }
    }
}
