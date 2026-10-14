using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Demiurge.Core.Native;

/// <summary>
/// Caché DNS (COL-16). DnsGetCacheDataTable no está documentada: si falla, se usa
/// "ipconfig /displaydns" como fallback.
/// </summary>
internal static partial class DnsCache
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DNS_CACHE_ENTRY
    {
        public IntPtr pNext;
        public IntPtr pszName;
        public ushort wType;
        public ushort wDataLength;
        public uint dwFlags;
    }

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable")]
    private static extern bool DnsGetCacheDataTable(out IntPtr ppEntry);

    [DllImport("dnsapi.dll", EntryPoint = "DnsFree")]
    private static extern void DnsFree(IntPtr p, int freeType);

    public sealed record Entry(string Name, string Type);

    public static List<Entry> Read()
    {
        try
        {
            var list = ReadNative();
            if (list.Count > 0) return list;
        }
        catch
        {
            // fallback abajo
        }
        return ReadIpconfig();
    }

    private static List<Entry> ReadNative()
    {
        var list = new List<Entry>();
        if (!DnsGetCacheDataTable(out var head) || head == IntPtr.Zero) return list;
        IntPtr cur = head;
        while (cur != IntPtr.Zero)
        {
            var e = Marshal.PtrToStructure<DNS_CACHE_ENTRY>(cur);
            var name = Marshal.PtrToStringUni(e.pszName);
            if (!string.IsNullOrEmpty(name)) list.Add(new Entry(name, TypeName(e.wType)));
            IntPtr next = e.pNext;
            if (e.pszName != IntPtr.Zero) DnsFree(e.pszName, 0);
            DnsFree(cur, 0);
            cur = next;
        }
        return list;
    }

    private static string TypeName(ushort t) => t switch
    {
        1 => "A", 5 => "CNAME", 12 => "PTR", 15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", 65 => "HTTPS",
        _ => t.ToString(),
    };

    [GeneratedRegex(@"^\s*(?:Record Name|Nombre de registro)[ .]*:\s*(\S+)", RegexOptions.Multiline)]
    private static partial Regex RecordName();

    private static List<Entry> ReadIpconfig()
    {
        var psi = new ProcessStartInfo("ipconfig", "/displaydns")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi);
        if (p is null) return [];
        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit(15000);
        return RecordName().Matches(output)
            .Select(m => m.Groups[1].Value.TrimEnd('.'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(n => new Entry(n, "?"))
            .ToList();
    }
}
