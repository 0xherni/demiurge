using System.Management;
using Demiurge.Core.Model;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-17: Microsoft Defender (estado, exclusiones, detecciones) y otros AV registrados en
/// root\SecurityCenter2.
/// </summary>
public sealed class DefenderCollector : ICollector
{
    public string Id => "COL-17";
    public string Name => "Antivirus";
    public int Order => 20;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var d = ctx.Snapshot.Defender;
        var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Defender");
        try
        {
            scope.Connect();
            foreach (var mo in Query(scope, "SELECT * FROM MSFT_MpComputerStatus"))
            {
                d.Available = true;
                d.AntivirusEnabled = mo["AntivirusEnabled"] as bool?;
                d.RealTimeProtectionEnabled = mo["RealTimeProtectionEnabled"] as bool?;
                d.TamperProtected = mo["IsTamperProtected"] as bool?;
                d.SignatureAgeDays = mo["AntivirusSignatureAge"] is { } age ? Convert.ToInt32(age) : null;
                if (mo["AntivirusSignatureLastUpdated"] is string s && s.Length > 0)
                    try { d.SignatureLastUpdated = ManagementDateTimeConverter.ToDateTime(s); } catch { }
            }
            foreach (var mo in Query(scope, "SELECT * FROM MSFT_MpPreference"))
            {
                d.ExclusionPaths.AddRange(RealValues(mo["ExclusionPath"]));
                d.ExclusionProcesses.AddRange(RealValues(mo["ExclusionProcess"]));
                d.ExclusionExtensions.AddRange(RealValues(mo["ExclusionExtension"]));
            }

            // Sin admin, Defender devuelve "N/A: Must be an administrator to view exclusions" en lugar de la lista.
            static IEnumerable<string> RealValues(object? raw) =>
                (raw as string[] ?? []).Where(v => !string.IsNullOrWhiteSpace(v) && !v.StartsWith("N/A", StringComparison.OrdinalIgnoreCase));
            foreach (var mo in Query(scope, "SELECT * FROM MSFT_MpThreatDetection"))
            {
                var det = new DefenderDetection
                {
                    ThreatName = mo["ThreatID"]?.ToString() ?? "",
                    Resources = (mo["Resources"] as string[] ?? []).ToList(),
                    Action = mo["ActionSuccess"]?.ToString(),
                };
                if (mo["InitialDetectionTime"] is string t && t.Length > 0)
                    try { det.Time = ManagementDateTimeConverter.ToDateTime(t); } catch { }
                d.Detections.Add(det);
            }
            // Nombres de amenazas
            var names = Query(scope, "SELECT ThreatID, ThreatName FROM MSFT_MpThreat")
                .ToDictionary(m => m["ThreatID"]?.ToString() ?? "", m => m["ThreatName"]?.ToString() ?? "");
            foreach (var det in d.Detections)
                if (names.TryGetValue(det.ThreatName, out var n)) det.ThreatName = n;
        }
        catch (ManagementException)
        {
            // Defender deshabilitado / reemplazado por otro AV
        }
        catch (UnauthorizedAccessException)
        {
            // Exclusiones requieren admin
        }

        // Otros AV (Security Center)
        try
        {
            foreach (var mo in Query(new ManagementScope(@"\\.\root\SecurityCenter2"), "SELECT displayName, productState FROM AntiVirusProduct"))
            {
                var name = mo["displayName"]?.ToString() ?? "";
                if (name.Contains("Defender", StringComparison.OrdinalIgnoreCase)) continue;
                uint state = Convert.ToUInt32(mo["productState"] ?? 0u);
                // bits 12-13 de productState: 0x1000 = protección activa.
                bool on = (state & 0x1000) != 0;
                d.OtherAntivirus.Add(on ? name : name + " (inactivo)");
            }
        }
        catch
        {
            // SecurityCenter2 no existe en Server
        }

        var settings = new List<SystemSetting>
        {
            new()
            {
                Name = "defender_rtp",
                Value = d.RealTimeProtectionEnabled?.ToString() ?? "desconocido",
                Expected = "True",
                Ok = d.RealTimeProtectionEnabled == true || d.OtherAntivirus.Any(a => !a.EndsWith("(inactivo)")),
            },
            new()
            {
                Name = "defender_signatures",
                Value = d.SignatureAgeDays?.ToString() ?? "desconocido",
                Expected = "≤ 7 días",
                Ok = d.SignatureAgeDays is null ? null : d.SignatureAgeDays <= 7,
            },
        };
        if (d.OtherAntivirus.Count > 0)
            settings.Add(new SystemSetting { Name = "other_av", Value = string.Join(", ", d.OtherAntivirus), Ok = true });

        // Cada exclusión es una entidad propia para poder colgarle findings (H-11) y acciones (quitarla).
        foreach (var p in d.ExclusionPaths)
            settings.Add(new SystemSetting { Name = "defender_exclusion_path", Value = p, Category = "infection" });
        foreach (var p in d.ExclusionProcesses)
            settings.Add(new SystemSetting { Name = "defender_exclusion_process", Value = p, Category = "infection" });
        foreach (var p in d.ExclusionExtensions)
            settings.Add(new SystemSetting { Name = "defender_exclusion_extension", Value = p, Category = "infection" });
        ctx.Snapshot.AddRange(ctx.Snapshot.Settings, settings);

        return Task.FromResult(CollectorResult.Of(d.ExclusionPaths.Count + d.ExclusionProcesses.Count + d.Detections.Count));
    }

    private static List<ManagementBaseObject> Query(ManagementScope scope, string q)
    {
        try
        {
            using var s = new ManagementObjectSearcher(scope, new ObjectQuery(q));
            return s.Get().Cast<ManagementBaseObject>().ToList();
        }
        catch (ManagementException)
        {
            return new();
        }
    }
}
