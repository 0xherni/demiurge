using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Demiurge.Core.Native;

/// <summary>Datos de proceso que .NET no expone: path real, integridad, elevación, usuario.</summary>
internal static class ProcessNative
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenUser = 1;
    private const int TokenElevation = 20;
    private const int TokenIntegrityLevel = 25;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int returnLength);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr h, out long creation, out long exit, out long kernel, out long user);

    public static string? GetImagePath(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }

    public static (long kernel100ns, long user100ns, DateTimeOffset? created)? GetTimes(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            if (!GetProcessTimes(h, out var c, out _, out var k, out var u)) return null;
            DateTimeOffset? created = c > 0 ? DateTimeOffset.FromFileTime(c) : null;
            return (k, u, created);
        }
        finally { CloseHandle(h); }
    }

    public sealed record TokenData(string? User, string? Integrity, bool Elevated);

    public static TokenData? GetTokenData(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            if (!OpenProcessToken(h, TOKEN_QUERY, out var token)) return null;
            try
            {
                return new TokenData(QueryUser(token), QueryIntegrity(token), QueryElevated(token));
            }
            finally { CloseHandle(token); }
        }
        finally { CloseHandle(h); }
    }

    private static IntPtr QueryInfo(IntPtr token, int cls)
    {
        GetTokenInformation(token, cls, IntPtr.Zero, 0, out int len);
        if (len <= 0) return IntPtr.Zero;
        IntPtr buf = Marshal.AllocHGlobal(len);
        if (GetTokenInformation(token, cls, buf, len, out _)) return buf;
        Marshal.FreeHGlobal(buf);
        return IntPtr.Zero;
    }

    private static string? QueryUser(IntPtr token)
    {
        IntPtr buf = QueryInfo(token, TokenUser);
        if (buf == IntPtr.Zero) return null;
        try
        {
            IntPtr pSid = Marshal.ReadIntPtr(buf);
            var sid = new SecurityIdentifier(pSid);
            try { return sid.Translate(typeof(NTAccount)).Value; }
            catch { return sid.Value; }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static string? QueryIntegrity(IntPtr token)
    {
        IntPtr buf = QueryInfo(token, TokenIntegrityLevel);
        if (buf == IntPtr.Zero) return null;
        try
        {
            IntPtr pSid = Marshal.ReadIntPtr(buf);
            int count = Marshal.ReadByte(GetSidSubAuthorityCount(pSid));
            int rid = Marshal.ReadInt32(GetSidSubAuthority(pSid, (uint)(count - 1)));
            return rid switch
            {
                < 0x1000 => "Untrusted",
                < 0x2000 => "Low",
                < 0x3000 => "Medium",
                < 0x4000 => "High",
                _ => "System",
            };
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static bool QueryElevated(IntPtr token)
    {
        IntPtr buf = QueryInfo(token, TokenElevation);
        if (buf == IntPtr.Zero) return false;
        try { return Marshal.ReadInt32(buf) != 0; }
        finally { Marshal.FreeHGlobal(buf); }
    }

    public static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator) || id.IsSystem;
    }
}
