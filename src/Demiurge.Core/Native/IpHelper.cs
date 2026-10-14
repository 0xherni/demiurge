using System.Net;
using System.Runtime.InteropServices;

namespace Demiurge.Core.Native;

/// <summary>Tablas TCP/UDP por PID (COL-14) vía iphlpapi.</summary>
internal static class IpHelper
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved = 0);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state, localAddr, localPort, remoteAddr, remotePort, owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct MIB_TCP6ROW_OWNER_PID
    {
        public fixed byte localAddr[16];
        public uint localScopeId, localPort;
        public fixed byte remoteAddr[16];
        public uint remoteScopeId, remotePort, state, owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr, localPort, owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct MIB_UDP6ROW_OWNER_PID
    {
        public fixed byte localAddr[16];
        public uint localScopeId, localPort, owningPid;
    }

    public sealed record Row(string Protocol, IPAddress Local, int LocalPort, IPAddress? Remote, int RemotePort, string State, int Pid);

    private static readonly string[] TcpStates =
        ["", "Closed", "Listen", "SynSent", "SynReceived", "Established", "FinWait1", "FinWait2", "CloseWait", "Closing", "LastAck", "TimeWait", "DeleteTcb"];

    public static List<Row> GetAll()
    {
        var rows = new List<Row>();
        rows.AddRange(Tcp4());
        rows.AddRange(Tcp6());
        rows.AddRange(Udp4());
        rows.AddRange(Udp6());
        return rows;
    }

    private static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    private static IntPtr Fetch(Func<IntPtr, int, (uint result, int size)> call, out int size)
    {
        size = 0;
        var (_, needed) = call(IntPtr.Zero, 0);
        for (int attempt = 0; attempt < 4; attempt++)
        {
            size = needed + 4096;
            IntPtr buf = Marshal.AllocHGlobal(size);
            var (res, n) = call(buf, size);
            if (res == 0) return buf;
            Marshal.FreeHGlobal(buf);
            needed = n;
        }
        return IntPtr.Zero;
    }

    private static IEnumerable<Row> Tcp4()
    {
        IntPtr buf = Fetch((p, s) => { int len = s; var r = GetExtendedTcpTable(p, ref len, false, AF_INET, TCP_TABLE_OWNER_PID_ALL); return (r, len); }, out _);
        if (buf == IntPtr.Zero) yield break;
        try
        {
            int count = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            int sz = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < count; i++, row += sz)
            {
                var r = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(row);
                var state = r.state < TcpStates.Length ? TcpStates[r.state] : r.state.ToString();
                var remote = new IPAddress(r.remoteAddr);
                bool listen = state == "Listen";
                yield return new Row("TCP", new IPAddress(r.localAddr), Port(r.localPort), listen ? null : remote, listen ? 0 : Port(r.remotePort), state, (int)r.owningPid);
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static unsafe IEnumerable<Row> Tcp6()
    {
        IntPtr buf = Fetch((p, s) => { int len = s; var r = GetExtendedTcpTable(p, ref len, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL); return (r, len); }, out _);
        if (buf == IntPtr.Zero) return [];
        var list = new List<Row>();
        try
        {
            int count = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            int sz = sizeof(MIB_TCP6ROW_OWNER_PID);
            for (int i = 0; i < count; i++, row += sz)
            {
                var r = (MIB_TCP6ROW_OWNER_PID*)row;
                var local = new IPAddress(new ReadOnlySpan<byte>(r->localAddr, 16), r->localScopeId);
                var remote = new IPAddress(new ReadOnlySpan<byte>(r->remoteAddr, 16), r->remoteScopeId);
                var state = r->state < TcpStates.Length ? TcpStates[r->state] : r->state.ToString();
                bool listen = state == "Listen";
                list.Add(new Row("TCP", local, Port(r->localPort), listen ? null : remote, listen ? 0 : Port(r->remotePort), state, (int)r->owningPid));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return list;
    }

    private static IEnumerable<Row> Udp4()
    {
        IntPtr buf = Fetch((p, s) => { int len = s; var r = GetExtendedUdpTable(p, ref len, false, AF_INET, UDP_TABLE_OWNER_PID); return (r, len); }, out _);
        if (buf == IntPtr.Zero) yield break;
        try
        {
            int count = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            int sz = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            for (int i = 0; i < count; i++, row += sz)
            {
                var r = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(row);
                yield return new Row("UDP", new IPAddress(r.localAddr), Port(r.localPort), null, 0, "", (int)r.owningPid);
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static unsafe IEnumerable<Row> Udp6()
    {
        IntPtr buf = Fetch((p, s) => { int len = s; var r = GetExtendedUdpTable(p, ref len, false, AF_INET6, UDP_TABLE_OWNER_PID); return (r, len); }, out _);
        if (buf == IntPtr.Zero) return [];
        var list = new List<Row>();
        try
        {
            int count = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            int sz = sizeof(MIB_UDP6ROW_OWNER_PID);
            for (int i = 0; i < count; i++, row += sz)
            {
                var r = (MIB_UDP6ROW_OWNER_PID*)row;
                var local = new IPAddress(new ReadOnlySpan<byte>(r->localAddr, 16), r->localScopeId);
                list.Add(new Row("UDP", local, Port(r->localPort), null, 0, "", (int)r->owningPid));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return list;
    }
}
