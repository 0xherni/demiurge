using System.Diagnostics.Eventing.Reader;
using Demiurge.Core.Model;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-23 (v2): eventos puntuales de alto valor. 7045 servicio instalado, 4720 cuenta creada,
/// 4732 agregado a grupo, 1102/104 log borrado, 4104 PowerShell script block, 1116/1117 Defender.
/// </summary>
public sealed class EventLogCollector : ICollector
{
    public string Id => "COL-23";
    public string Name => "Registro de eventos";
    public int Order => 30; // después de COL-19: corrige la fecha de creación de cuentas

    private sealed record Source(string Log, int[] Ids, int Max, Func<EventRecord, bool>? Filter = null);

    private static readonly string[] SuspiciousScriptTokens =
    [
        "FromBase64String", "IEX", "Invoke-Expression", "DownloadString", "DownloadFile", "Net.WebClient",
        "Invoke-WebRequest", "Start-BitsTransfer", "-EncodedCommand", "Reflection.Assembly", "VirtualAlloc",
        "AmsiUtils", "Add-MpPreference", "Set-MpPreference", "bypass", "-w hidden", "WindowStyle Hidden",
    ];

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var ms = (long)TimeSpan.FromDays(ctx.Options.EventLogDays).TotalMilliseconds;
        var sources = new[]
        {
            new Source("System", [7045, 104], 500),
            new Source("Security", [4720, 4732, 1102], 500),
            new Source("Microsoft-Windows-PowerShell/Operational", [4104], 300, e =>
            {
                var text = e.Properties.Count > 2 ? e.Properties[2].Value?.ToString() ?? "" : "";
                return SuspiciousScriptTokens.Any(t => text.Contains(t, StringComparison.OrdinalIgnoreCase));
            }),
            new Source("Microsoft-Windows-Windows Defender/Operational", [1116, 1117], 300),
        };

        var list = new List<EventInfo>();
        var warnings = new List<string>();
        foreach (var src in sources)
        {
            try
            {
                var ids = string.Join(" or ", src.Ids.Select(i => $"EventID={i}"));
                var q = new EventLogQuery(src.Log, PathType.LogName, $"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]")
                { ReverseDirection = true };
                using var reader = new EventLogReader(q);
                int n = 0;
                for (var e = reader.ReadEvent(); e is not null && n < src.Max; e = reader.ReadEvent())
                {
                    ct.ThrowIfCancellationRequested();
                    using (e)
                    {
                        if (src.Filter is not null && !src.Filter(e)) continue;
                        list.Add(Convert(src.Log, e));
                        n++;
                    }
                }
            }
            catch (EventLogNotFoundException)
            {
                // log inexistente
            }
            catch (UnauthorizedAccessException)
            {
                warnings.Add($"Sin permisos para leer {src.Log} (requiere SYSTEM/admin)");
            }
            catch (EventLogException ex)
            {
                warnings.Add($"{src.Log}: {ex.Message}");
            }
        }

        // Fecha de creación real de cuentas (corrige la aproximación de COL-19).
        foreach (var ev in list.Where(e => e.EventId == 4720))
        {
            var name = ev.Data.GetValueOrDefault("TargetUserName");
            var acc = ctx.Snapshot.Accounts.FirstOrDefault(a => string.Equals(a.Name, name, StringComparison.OrdinalIgnoreCase));
            if (acc is not null) acc.Created = ev.Timestamp;
        }

        ctx.Snapshot.AddRange(ctx.Snapshot.Events, list);
        return Task.FromResult(new CollectorResult { ItemCount = list.Count, Warnings = warnings });
    }

    private static EventInfo Convert(string log, EventRecord e)
    {
        var info = new EventInfo
        {
            Log = log,
            EventId = e.Id,
            Timestamp = e.TimeCreated ?? DateTime.Now,
            Provider = e.ProviderName,
            RecordId = e.RecordId ?? 0,
        };
        // Nombres de campos desde el XML del evento (EventData/Data@Name).
        try
        {
            var xml = System.Xml.Linq.XElement.Parse(e.ToXml());
            XNamespaceHelper.Fill(xml, info.Data);
        }
        catch
        {
            for (int i = 0; i < e.Properties.Count; i++)
                info.Data[$"p{i}"] = e.Properties[i].Value?.ToString() ?? "";
        }
        if (info.Data.TryGetValue("ScriptBlockText", out var sb) && sb.Length > 4000)
            info.Data["ScriptBlockText"] = sb[..4000] + "…";
        return info;
    }
}

internal static class XNamespaceHelper
{
    public static void Fill(System.Xml.Linq.XElement root, Dictionary<string, string> data)
    {
        foreach (var el in root.Descendants().Where(d => d.Name.LocalName == "Data"))
        {
            var name = el.Attribute("Name")?.Value ?? $"p{data.Count}";
            data[name] = el.Value;
        }
        foreach (var el in root.Descendants().Where(d => d.Parent?.Name.LocalName == "UserData" || d.Parent?.Parent?.Name.LocalName == "UserData"))
            if (!el.HasElements) data.TryAdd(el.Name.LocalName, el.Value);
    }
}
