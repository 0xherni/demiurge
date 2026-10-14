using System.Collections.Concurrent;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using Demiurge.Core.Model;
using Demiurge.Core.Native;
using Demiurge.Core.Util;

namespace Demiurge.Core.Live;

/// <summary>
/// Sesión ETW permanente (COL-02, COL-03, COL-04, COL-05). Usa providers manifest-based
/// (permiten varias sesiones) en lugar del NT Kernel Logger (sesión única global).
/// </summary>
public sealed class LiveMonitor : ILiveTelemetrySource, IDisposable
{
    public const string SessionName = "Demiurge-Live";

    private const string KernelProcess = "Microsoft-Windows-Kernel-Process";
    private const string KernelNetwork = "Microsoft-Windows-Kernel-Network";
    private const string DnsClient = "Microsoft-Windows-DNS-Client";

    private static readonly TimeSpan Retention = TimeSpan.FromHours(24);
    private const int MaxProcesses = 20000;
    private const int MaxModules = 20000;
    private const int MaxDns = 20000;
    private const int MaxFlows = 20000;

    private readonly ILogger _logger;
    private TraceEventSession? _session;
    private Thread? _thread;

    private readonly ConcurrentDictionary<int, ProcessInfo> _running = new();
    private readonly ConcurrentQueue<ProcessInfo> _finished = new();
    private readonly ConcurrentQueue<ModuleLoadInfo> _modules = new();
    private readonly ConcurrentDictionary<string, DnsQueryInfo> _dns = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, NetworkFlow> _flows = new();

    /// <summary>Se dispara al ver un proceso nuevo (con cmdline si se alcanzó a leer).</summary>
    public event Action<ProcessInfo>? ProcessStarted;
    /// <summary>Se dispara al terminar un proceso (para detectar efímeros, H-23).</summary>
    public event Action<ProcessInfo>? ProcessStopped;
    public event Action<NetworkFlow>? NewFlow;
    public event Action<DnsQueryInfo>? NewDomain;
    public event Action<ModuleLoadInfo>? ModuleLoaded;

    public LiveMonitor(ILogger logger) => _logger = logger;

    public bool IsRunning => _session is not null && _thread is { IsAlive: true };

    public void Start()
    {
        if (IsRunning) return;
        if (!(TraceEventSession.IsElevated() ?? false))
        {
            _logger.LogWarning("Modo vivo deshabilitado: ETW requiere privilegios de administrador/SYSTEM");
            return;
        }

        _session = new TraceEventSession(SessionName, TraceEventSessionOptions.Create) { StopOnDispose = true };
        // Keywords Kernel-Process: 0x10 PROCESS, 0x40 IMAGE.
        _session.EnableProvider(KernelProcess, TraceEventLevel.Informational, 0x10 | 0x40);
        // Keywords Kernel-Network: 0x10 IPv4, 0x20 IPv6.
        _session.EnableProvider(KernelNetwork, TraceEventLevel.Informational, 0x10 | 0x20);
        _session.EnableProvider(DnsClient, TraceEventLevel.Informational, ulong.MaxValue);
        _session.Source.Dynamic.All += OnEvent;

        _thread = new Thread(() =>
        {
            try { _session.Source.Process(); }
            catch (Exception ex) { _logger.LogError(ex, "Sesión ETW terminada con error"); }
        })
        { IsBackground = true, Name = "Demiurge ETW" };
        _thread.Start();
        _logger.LogInformation("Modo vivo iniciado (sesión ETW {Session})", SessionName);
    }

    public void Stop()
    {
        try { _session?.Dispose(); } catch { }
        _session = null;
    }

    public void Dispose() => Stop();

    private void OnEvent(TraceEvent e)
    {
        try
        {
            switch (e.ProviderName)
            {
                case KernelProcess: OnProcess(e); break;
                case KernelNetwork: OnNetwork(e); break;
                case DnsClient: OnDns(e); break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error procesando evento ETW {Provider}/{Id}", e.ProviderName, (int)e.ID);
        }
    }

    private void OnProcess(TraceEvent e)
    {
        switch ((int)e.ID)
        {
            case 1: // ProcessStart
            {
                int pid = ToInt(e.PayloadByName("ProcessID"));
                var image = DevicePath.ToDosPath(e.PayloadByName("ImageName")?.ToString() ?? "");
                var p = new ProcessInfo
                {
                    Pid = pid,
                    ParentPid = ToInt(e.PayloadByName("ParentProcessID")),
                    SessionId = ToInt(e.PayloadByName("SessionID")),
                    Name = Path.GetFileName(image),
                    Path = image,
                    StartTime = e.TimeStamp,
                    // El provider manifest no trae cmdline: la leemos ya mismo del proceso vivo.
                    CommandLine = DevicePath.GetCommandLine(pid),
                };
                _running[pid] = p;
                ProcessStarted?.Invoke(p);
                break;
            }
            case 2: // ProcessStop
            {
                int pid = ToInt(e.PayloadByName("ProcessID"));
                if (_running.TryRemove(pid, out var p))
                {
                    p.EndTime = e.TimeStamp;
                    p.Ephemeral = p.StartTime is not null && p.EndTime - p.StartTime < TimeSpan.FromSeconds(10);
                    _finished.Enqueue(p);
                    Trim(_finished, MaxProcesses, x => x.EndTime ?? x.StartTime ?? DateTimeOffset.MinValue);
                    ProcessStopped?.Invoke(p);
                }
                break;
            }
            case 5: // ImageLoad
            {
                var image = DevicePath.ToDosPath(e.PayloadByName("ImageName")?.ToString() ?? "");
                // Alto volumen: sólo nos quedamos con DLLs fuera de Windows/Program Files.
                if (image.Length == 0 || PathClassifier.IsInWindowsDir(image) || PathClassifier.IsProgramFiles(image)) return;
                int pid = ToInt(e.PayloadByName("ProcessID"));
                var m = new ModuleLoadInfo
                {
                    Pid = pid,
                    Path = image,
                    ProcessName = _running.TryGetValue(pid, out var p) ? p.Name : null,
                    Timestamp = e.TimeStamp,
                };
                _modules.Enqueue(m);
                Trim(_modules, MaxModules, x => x.Timestamp);
                ModuleLoaded?.Invoke(m);
                break;
            }
        }
    }

    private void OnNetwork(TraceEvent e)
    {
        int id = (int)e.ID;
        // IPv4: 10 send, 11 recv, 12 connect, 15 accept, 42 udp send, 43 udp recv.
        // IPv6: 26 send, 27 recv, 28 connect, 31 accept, 58 udp send, 59 udp recv.
        bool send = id is 10 or 26 or 42 or 58;
        bool recv = id is 11 or 27 or 43 or 59;
        bool connect = id is 12 or 28 or 15 or 31;
        if (!send && !recv && !connect) return;

        int pid = ToInt(e.PayloadByName("PID"));
        var daddr = e.PayloadByName("daddr")?.ToString() ?? "";
        int dport = ToInt(e.PayloadByName("dport"));
        long size = ToLong(e.PayloadByName("size"));
        if (daddr.Length == 0) return;
        string proto = id is 42 or 43 or 58 or 59 ? "UDP" : "TCP";

        var key = $"{pid}|{proto}|{daddr}|{dport}";
        bool isNew = false;
        var flow = _flows.GetOrAdd(key, _ =>
        {
            isNew = true;
            return new NetworkFlow
            {
                Pid = pid,
                Protocol = proto,
                RemoteAddress = daddr,
                RemotePort = dport,
                First = e.TimeStamp,
                ProcessName = _running.TryGetValue(pid, out var p) ? p.Name : null,
            };
        });
        lock (flow)
        {
            flow.Last = e.TimeStamp;
            if (send) flow.BytesOut += size;
            if (recv) flow.BytesIn += size;
            if (connect)
            {
                flow.Connects.Add(e.TimeStamp);
                if (flow.Connects.Count > 200) flow.Connects.RemoveRange(0, flow.Connects.Count - 200);
            }
        }
        if (isNew)
        {
            if (_flows.Count > MaxFlows) TrimFlows();
            NewFlow?.Invoke(flow);
        }
    }

    private void OnDns(TraceEvent e)
    {
        if ((int)e.ID is not (3008 or 3006 or 3020)) return;
        var name = e.PayloadByName("QueryName")?.ToString()?.TrimEnd('.');
        if (string.IsNullOrEmpty(name)) return;
        int pid = e.ProcessID;
        var q = new DnsQueryInfo
        {
            Domain = name,
            Pid = pid,
            ProcessName = _running.TryGetValue(pid, out var p) ? p.Name : null,
            RecordType = e.PayloadByName("QueryType")?.ToString(),
            Response = e.PayloadByName("QueryResults")?.ToString(),
            Timestamp = e.TimeStamp,
            Source = "etw",
        };
        bool isNew = _dns.TryAdd(name, q);
        if (!isNew)
        {
            _dns[name] = q;
            return;
        }
        if (_dns.Count > MaxDns)
        {
            foreach (var old in _dns.Values.OrderBy(d => d.Timestamp).Take(_dns.Count - MaxDns).ToList())
                _dns.TryRemove(old.Domain, out _);
        }
        NewDomain?.Invoke(q);
    }

    // ---------------- ILiveTelemetrySource ----------------

    public IReadOnlyList<DnsQueryInfo> RecentDnsQueries() => _dns.Values.ToList();

    public IReadOnlyList<ProcessInfo> RecentProcesses() =>
        _finished.Where(p => p.EndTime > DateTimeOffset.Now - Retention).ToList();

    public IReadOnlyList<ModuleLoadInfo> RecentModuleLoads() =>
        _modules.Where(m => m.Timestamp > DateTimeOffset.Now - Retention).ToList();

    public IReadOnlyList<NetworkFlow> RecentFlows()
    {
        var list = new List<NetworkFlow>();
        foreach (var f in _flows.Values)
            lock (f) list.Add(new NetworkFlow
            {
                Pid = f.Pid, ProcessName = f.ProcessName, Protocol = f.Protocol, RemoteAddress = f.RemoteAddress,
                RemotePort = f.RemotePort, BytesIn = f.BytesIn, BytesOut = f.BytesOut, First = f.First, Last = f.Last,
                Connects = f.Connects.ToList(),
            });
        return list;
    }

    // ---------------- helpers ----------------

    private void TrimFlows()
    {
        foreach (var old in _flows.OrderBy(kv => kv.Value.Last).Take(_flows.Count - MaxFlows + 1000).ToList())
            _flows.TryRemove(old.Key, out _);
    }

    private static void Trim<T>(ConcurrentQueue<T> q, int max, Func<T, DateTimeOffset> ts)
    {
        var cutoff = DateTimeOffset.Now - Retention;
        while (q.Count > max || (q.TryPeek(out var head) && ts(head) < cutoff))
            if (!q.TryDequeue(out _)) break;
    }

    private static int ToInt(object? o) => o is null ? 0 : Convert.ToInt32(o);
    private static long ToLong(object? o) => o is null ? 0 : Convert.ToInt64(o);
}
