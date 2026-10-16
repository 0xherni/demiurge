using System.Diagnostics.Eventing.Reader;
using System.IO.Compression;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Demiurge.Core.Model;
using Demiurge.Core.Native;
using Demiurge.Core.Util;

namespace Demiurge.Core.External;

/// <summary>
/// EXT-01: YARA-X (CLI "yr") sobre los binarios elegidos (procesos, arranque, descargas, sospechosos).
/// Un solo proceso para toda la lista (--scan-list) y reglas compiladas EN MEMORIA en cada escaneo: no se guarda
/// un archivo de reglas compiladas en disco porque el antivirus lo bloquea (contiene miles de patrones de malware)
/// y la "solución" de excluirlo del antivirus es justamente lo que hace el malware.
/// </summary>
public sealed class YaraXScanner
{
    private readonly ExternalRunner _runner;
    private readonly DemiurgeOptions _options;
    private readonly ILogger _logger;

    public YaraXScanner(ExternalRunner runner, DemiurgeOptions options, ILogger logger)
    {
        _runner = runner;
        _options = options;
        _logger = logger;
    }

    public static string DefaultRulesDir => DemiurgePaths.Ensure(Path.Combine(DemiurgePaths.Rules, "yara"));

    public static bool HasRules(DemiurgeOptions o) => RuleFiles(o).Count > 0;

    private static List<string> RuleFiles(DemiurgeOptions o)
    {
        var rules = o.YaraX.RulesPath ?? DefaultRulesDir;
        if (File.Exists(rules)) return [rules];
        if (!Directory.Exists(rules)) return [];
        return Directory.EnumerateFiles(rules, "*.yar", SearchOption.AllDirectories)
            .Where(Security.DataDirectoryLockdown.CanTrust).ToList();
    }

    public async Task<List<ExternalDetection>> ScanAsync(IEnumerable<string> targets, CancellationToken ct)
    {
        var exe = _runner.Verify(_options.YaraX, out var error);
        if (exe is null) { _logger.LogInformation("YARA-X no se ejecuta: {Error}", error); return new(); }
        var ruleFiles = RuleFiles(_options);
        if (ruleFiles.Count == 0) { _logger.LogInformation("YARA-X: todavía no hay reglas (se descargan al abrir la app con internet)"); return new(); }

        var files = targets.Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(f => { try { var fi = new FileInfo(f); return fi.Exists && fi.Length <= 64L * 1024 * 1024; } catch { return false; } })
            .ToList();
        if (files.Count == 0) return new();

        // Lista de archivos en nuestra carpeta protegida (nadie puede cambiarla en el medio).
        var list = Path.Combine(DemiurgePaths.Ensure(Path.Combine(DemiurgePaths.Root, "tmp")), $"yara_{Guid.NewGuid():N}.txt");
        await File.WriteAllLinesAsync(list, files, ct).ConfigureAwait(false);
        try
        {
            var args = new List<string>(ruleFiles) { list, "--scan-list", "--ignore-invalid-rules", "--relaxed-re-syntax", "--disable-warnings",
                "--output-format", "ndjson", "--disable-console-logs", "--print-meta", "--timeout", "30",
                "--threads", Math.Clamp(Environment.ProcessorCount / 2, 1, 8).ToString() };
            args.Insert(0, "scan");
            var r = await _runner.RunAsync(exe, args, TimeSpan.FromMinutes(20), ct).ConfigureAwait(false);
            if (r.ExitCode != 0 && r.StdOut.Length == 0)
                _logger.LogWarning("YARA-X terminó con código {Code}: {Error}", r.ExitCode, r.StdErr.Length > 300 ? r.StdErr[..300] : r.StdErr);
            var dets = ParseNdjson(r.StdOut, "");
            _logger.LogInformation("YARA-X revisó {Count} archivos: {Hits} coincidencia(s)", files.Count, dets.Count);
            return dets;
        }
        finally
        {
            try { File.Delete(list); } catch { }
        }
    }

    internal static List<ExternalDetection> ParseNdjson(string output, string fallbackPath)
    {
        var list = new List<ExternalDetection>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!line.StartsWith('{')) continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                var path = root.TryGetProperty("path", out var p) ? p.GetString() ?? fallbackPath : fallbackPath;
                if (!root.TryGetProperty("rules", out var rules)) continue;
                foreach (var rule in rules.EnumerateArray())
                {
                    var id = rule.TryGetProperty("identifier", out var i) ? i.GetString() ?? "?" : "?";
                    var det = new ExternalDetection { Tool = "EXT-01", Rule = id, TargetPath = path };
                    // yr 1.x: "meta": [["clave", valor], ...] (versiones viejas usaban "metadata").
                    if (rule.TryGetProperty("meta", out var meta) || rule.TryGetProperty("metadata", out meta))
                    {
                        foreach (var m in meta.ValueKind == JsonValueKind.Array ? meta.EnumerateArray().ToList() : [])
                        {
                            if (m.ValueKind != JsonValueKind.Array || m.GetArrayLength() < 2) continue;
                            var k = m[0].GetString() ?? "";
                            var v = m[1].ValueKind == JsonValueKind.String ? m[1].GetString() ?? "" : m[1].ToString();
                            det.Data[k] = v;
                            if (k is "malware_family" or "family" or "malware" or "malpedia_family") det.Family = v;
                            if (k is "mitre_attack" or "attack") det.AttackIds.AddRange(v.Split(',', ' ').Where(x => x.StartsWith('T')));
                        }
                    }
                    det.Family ??= FamilyFrom(det.Data.GetValueOrDefault("description"), id);
                    if (det.Data.TryGetValue("score", out var score)) det.Level = score;
                    list.Add(det);
                }
            }
            catch (JsonException)
            {
                // línea no JSON
            }
        }
        return list;
    }

    /// <summary>"Detects RedLine Stealer payload" → "RedLine Stealer payload"; si no hay descripción, el nombre de la regla.</summary>
    internal static string FamilyFrom(string? description, string ruleId)
    {
        if (!string.IsNullOrWhiteSpace(description))
        {
            var d = description.Trim().TrimEnd('.');
            foreach (var prefix in new[] { "Detects ", "Detect ", "Detection of ", "Identifies ", "Finds " })
                if (d.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) { d = d[prefix.Length..]; break; }
            return d.Length > 120 ? d[..117] + "…" : d;
        }
        return ruleId;
    }

    /// <summary>TI-09: descarga reglas core de YARA Forge (semanal).</summary>
    public static async Task<bool> UpdateRulesAsync(HttpClient http, ILogger logger, CancellationToken ct)
    {
        const string url = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";
        var dir = DefaultRulesDir;
        var marker = Path.Combine(dir, ".updated");
        if (File.Exists(marker) && DateTime.UtcNow - File.GetLastWriteTimeUtc(marker) < TimeSpan.FromDays(7)) return false;
        try
        {
            var bytes = await http.GetByteArrayAsync(url, ct).ConfigureAwait(false);
            using var zip = new ZipArchive(new MemoryStream(bytes));
            // Sólo el nombre del archivo (nunca carpetas del zip) y con topes de tamaño: un zip manipulado no puede escribir
            // fuera de la carpeta de reglas ni llenar el disco.
            long total = 0;
            foreach (var entry in zip.Entries.Where(e => e.Name.EndsWith(".yar", StringComparison.OrdinalIgnoreCase)))
            {
                if (entry.Length > 32L * 1024 * 1024 || (total += entry.Length) > 512L * 1024 * 1024)
                    throw new InvalidDataException("El paquete de reglas YARA es más grande de lo esperado; no se usa.");
                if (entry.Name != Path.GetFileName(entry.Name) || entry.Name.StartsWith('.')) continue;
                entry.ExtractToFile(Path.Combine(dir, entry.Name), overwrite: true);
            }
            // Atribución requerida por las licencias de las reglas.
            await File.WriteAllTextAsync(Path.Combine(dir, "CREDITS.txt"),
                "Reglas YARA de YARA Forge (https://github.com/YARAHQ/yara-forge). Cada regla conserva su autor y licencia en sus metadatos.\n" +
                "signature-base (Neo23x0) se distribuye bajo Detection Rule License 1.1 (atribución requerida).\n", ct).ConfigureAwait(false);
            await File.WriteAllTextAsync(marker, DateTime.UtcNow.ToString("O"), ct).ConfigureAwait(false);
            logger.LogInformation("Reglas YARA Forge actualizadas");
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning("No se pudieron actualizar las reglas YARA: {Error}", ex.Message);
            return false;
        }
    }
}

/// <summary>EXT-02: PE-sieve / HollowsHunter sobre memoria de procesos (hollowing, inyecciones, hooks, shellcode).</summary>
public sealed class HollowsHunterScanner
{
    private readonly ExternalRunner _runner;
    private readonly DemiurgeOptions _options;
    private readonly ILogger _logger;

    public HollowsHunterScanner(ExternalRunner runner, DemiurgeOptions options, ILogger logger)
    {
        _runner = runner;
        _options = options;
        _logger = logger;
    }

    public async Task<List<ExternalDetection>> ScanAsync(IReadOnlyCollection<int>? pids, CancellationToken ct)
    {
        var exe = _runner.Verify(_options.HollowsHunter, out var error);
        if (exe is null) { _logger.LogInformation("HollowsHunter no se ejecuta: {Error}", error); return new(); }
        var outDir = DemiurgePaths.Ensure(Path.Combine(DemiurgePaths.Root, "hh_out"));
        var args = new List<string> { "/json", "/quiet", "/ofilter", "2", "/dir", outDir };
        if (pids is { Count: > 0 })
        {
            args.Add("/pid");
            args.Add(string.Join(";", pids));
        }
        // Nunca /kill ni /suspend: Demiurge sólo observa.
        var r = await _runner.RunAsync(exe, args, TimeSpan.FromSeconds(_options.HollowsHunter.TimeoutSeconds), ct).ConfigureAwait(false);
        try { Directory.Delete(outDir, true); } catch { }
        var dets = Parse(r.StdOut);
        _logger.LogInformation("HollowsHunter revisó {Scope}: {Hits} proceso(s) con anomalías", pids is null ? "todos los procesos" : $"{pids.Count} proceso(s)", dets.Count);
        return dets;
    }

    internal static List<ExternalDetection> Parse(string output)
    {
        var list = new List<ExternalDetection>();
        int start = output.IndexOf('{');
        if (start < 0) return list;
        try
        {
            using var doc = JsonDocument.Parse(output[start..]);
            if (!doc.RootElement.TryGetProperty("suspicious", out var sus)) return list;
            foreach (var s in sus.EnumerateArray())
            {
                int pid = s.TryGetProperty("pid", out var p) ? p.GetInt32() : 0;
                var name = s.TryGetProperty("name", out var n) ? n.GetString() : null;
                var kinds = new List<string>();
                foreach (var (key, label) in new[] { ("replaced", "módulo reemplazado (hollowing)"), ("implanted_pe", "PE inyectado"), ("implanted_shc", "shellcode"), ("implanted", "código inyectado"), ("hdr_mod", "cabecera modificada"), ("patched", "código parcheado"), ("iat_hooked", "hooks en IAT"), ("unreachable_file", "archivo original inaccesible") })
                    if (s.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Number && v.GetInt32() > 0) kinds.Add(label);
                if (kinds.Count == 0) continue;
                // "patched"/"iat_hooked" solos son comunes en software legítimo (anti-cheat, overlays): no cuentan.
                if (kinds.All(k => k is "código parcheado" or "hooks en IAT" or "cabecera modificada")) continue;
                list.Add(new ExternalDetection
                {
                    Tool = "EXT-02",
                    Rule = string.Join(", ", kinds),
                    Pid = pid,
                    TargetPath = name,
                    AttackIds = ["T1055"],
                    Data = { ["detail"] = string.Join(", ", kinds) },
                });
            }
        }
        catch (JsonException)
        {
            // salida inesperada
        }
        return list;
    }
}

/// <summary>
/// EXT-03: Hayabusa (miles de reglas Sigma sobre todos los registros de eventos). Se usa la edición "live-response",
/// que trae las reglas codificadas junto al ejecutable (encoded_rules.yml): no hay miles de archivos de reglas que el
/// antivirus pueda confundir con malware. AGPL: se invoca como programa aparte, nunca se linkea.
/// </summary>
public sealed class HayabusaScanner
{
    private readonly ExternalRunner _runner;
    private readonly DemiurgeOptions _options;
    private readonly ILogger _logger;

    public HayabusaScanner(ExternalRunner runner, DemiurgeOptions options, ILogger logger)
    {
        _runner = runner;
        _options = options;
        _logger = logger;
    }

    /// <param name="days">Ventana hacia atrás (escaneo normal: 7 días; profundo: 30).</param>
    public async Task<List<ExternalDetection>> ScanAsync(int days, CancellationToken ct)
    {
        var exe = _runner.Verify(_options.Hayabusa, out var error);
        if (exe is null) { _logger.LogInformation("Hayabusa no se ejecuta: {Error}", error); return new(); }
        if (!ProcessNative.IsAdministrator()) { _logger.LogInformation("Hayabusa necesita permisos de administrador para leer los registros"); return new(); }
        // Salida en nuestra carpeta protegida.
        var output = Path.Combine(DemiurgePaths.Ensure(Path.Combine(DemiurgePaths.Root, "tmp")), $"hayabusa_{Guid.NewGuid():N}.jsonl");
        try
        {
            // dfir-timeline (v4): -l análisis en vivo, sólo reglas de nivel alto o más, JSONL con perfil "verbose" (incluye MITRE),
            // sin asistente (-w), sin banner (-q), sin color (-K), sin guardar logs de errores (-Q), fechas ISO (-O).
            var args = new List<string> { "dfir-timeline", "-l", "--time-offset", $"{days}d", "-m", "high", "-t", "jsonl", "-p", "verbose",
                "-o", output, "-w", "-q", "-K", "-C", "-Q", "-O" };
            var r = await _runner.RunAsync(exe, args, TimeSpan.FromSeconds(_options.Hayabusa.TimeoutSeconds), ct).ConfigureAwait(false);
            var dets = File.Exists(output) ? Parse(await File.ReadAllLinesAsync(output, ct).ConfigureAwait(false)) : new();
            _logger.LogInformation("Hayabusa revisó los registros de eventos ({Days} días): {Rules} regla(s) con coincidencias (código {Code})", days, dets.Count, r.ExitCode);
            return dets;
        }
        finally
        {
            try { File.Delete(output); } catch { }
        }
    }

    internal static List<ExternalDetection> Parse(IEnumerable<string> lines)
    {
        // Volumen alto: agrupamos por regla para resumir al usuario.
        var byRule = new Dictionary<string, ExternalDetection>();
        foreach (var line in lines)
        {
            if (!line.TrimStart().StartsWith('{')) continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                var r = doc.RootElement;
                var title = r.TryGetProperty("RuleTitle", out var t) ? t.GetString() ?? "?" : "?";
                var level = r.TryGetProperty("Level", out var l) ? l.GetString() ?? "" : "";
                level = level switch { "emer" or "emerg" or "emergency" => "critical", "crit" => "critical", "med" => "medium", "info" => "informational", _ => level };
                if (!byRule.TryGetValue(title, out var det))
                {
                    det = new ExternalDetection { Tool = "EXT-03", Rule = title, Level = level };
                    if (r.TryGetProperty("MitreTags", out var tags))
                        det.AttackIds.AddRange(tags.ToString().Split([',', ' ', '[', ']', '"'], StringSplitOptions.RemoveEmptyEntries).Where(x => x.StartsWith('T') && x.Length >= 5));
                    det.Data["count"] = "0";
                    byRule[title] = det;
                }
                det.Data["count"] = (int.Parse(det.Data["count"]) + 1).ToString();
                if (r.TryGetProperty("Timestamp", out var ts) && string.CompareOrdinal(ts.ToString(), det.Data.GetValueOrDefault("last") ?? "") > 0) det.Data["last"] = ts.ToString();
                if (r.TryGetProperty("Channel", out var ch)) det.Data["channel"] = ch.ToString();
                if (r.TryGetProperty("EventID", out var eid)) det.Data["eventId"] = eid.ToString();
                if (r.TryGetProperty("Details", out var d)) det.Data["detail"] = d.ToString().Length > 300 ? d.ToString()[..300] : d.ToString();
            }
            catch (JsonException)
            {
                // ignorar
            }
        }
        return byRule.Values.ToList();
    }
}

/// <summary>
/// EXT-04 (opt-in): si el usuario ya tiene Sysmon instalado, se lee su log como historial de procesos. Demiurge no lo
/// descarga ni lo instala (ese código se quitó: instalar software desde internet en un proceso elevado es superficie de
/// ataque que no hace falta).
/// </summary>
public static class SysmonIntegration
{
    public const string LogName = "Microsoft-Windows-Sysmon/Operational";

    public static bool IsInstalled()
    {
        try
        {
            using var s = new EventLogSession();
            return s.GetLogNames().Contains(LogName);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Lee creación de procesos (evento 1) de los últimos días como historial previo.</summary>
    public static List<ProcessInfo> ReadProcessHistory(int days, int max = 5000)
    {
        var list = new List<ProcessInfo>();
        if (!IsInstalled()) return list;
        try
        {
            var ms = (long)TimeSpan.FromDays(days).TotalMilliseconds;
            var q = new EventLogQuery(LogName, PathType.LogName, $"*[System[EventID=1 and TimeCreated[timediff(@SystemTime) <= {ms}]]]") { ReverseDirection = true };
            using var reader = new EventLogReader(q);
            for (var e = reader.ReadEvent(); e is not null && list.Count < max; e = reader.ReadEvent())
            {
                using (e)
                {
                    var data = new Dictionary<string, string>();
                    XNamespaceHelperPublic.Fill(System.Xml.Linq.XElement.Parse(e.ToXml()), data);
                    var image = data.GetValueOrDefault("Image") ?? "";
                    list.Add(new ProcessInfo
                    {
                        Pid = int.TryParse(data.GetValueOrDefault("ProcessId"), out var pid) ? pid : 0,
                        ParentPid = int.TryParse(data.GetValueOrDefault("ParentProcessId"), out var ppid) ? ppid : 0,
                        Name = Path.GetFileName(image),
                        Path = image,
                        CommandLine = data.GetValueOrDefault("CommandLine"),
                        User = data.GetValueOrDefault("User"),
                        StartTime = e.TimeCreated,
                        EndTime = e.TimeCreated, // histórico: ya no está corriendo (o no lo sabemos)
                    });
                }
            }
        }
        catch
        {
            // sin permisos
        }
        return list;
    }
}

internal static class XNamespaceHelperPublic
{
    public static void Fill(System.Xml.Linq.XElement root, Dictionary<string, string> data)
    {
        foreach (var el in root.Descendants().Where(d => d.Name.LocalName == "Data"))
            data[el.Attribute("Name")?.Value ?? $"p{data.Count}"] = el.Value;
    }
}

/// <summary>
/// Microsoft Defender como motor: le pide que analice archivos puntuales con su comando oficial (MpCmdRun), con
/// -DisableRemediation para que NO borre nada por su cuenta: la decisión queda en el usuario, con la tarjeta explicada.
/// </summary>
public sealed class DefenderScanner
{
    private readonly ExternalRunner _runner;
    private readonly ILogger _logger;

    public DefenderScanner(ExternalRunner runner, ILogger logger)
    {
        _runner = runner;
        _logger = logger;
    }

    /// <summary>MpCmdRun de la plataforma más nueva (se actualiza aparte de Windows), o el de Program Files.</summary>
    public static string? Locate()
    {
        var candidates = new List<string>();
        var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform");
        if (Directory.Exists(platform))
            candidates.AddRange(Directory.EnumerateDirectories(platform).OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase).Select(d => Path.Combine(d, "MpCmdRun.exe")));
        candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe"));
        return candidates.FirstOrDefault(File.Exists);
    }

    public async Task<List<ExternalDetection>> ScanAsync(IReadOnlyCollection<string> files, IProgress<string>? progress, CancellationToken ct)
    {
        var result = new List<ExternalDetection>();
        var exe = Locate();
        if (exe is null) { _logger.LogInformation("Microsoft Defender no está disponible en esta PC"); return result; }
        // Sólo se ejecuta el MpCmdRun auténtico, firmado por Microsoft.
        var sig = WinTrust.Verify(exe);
        if (!sig.IsMicrosoft) { _logger.LogWarning("{Exe} no tiene firma válida de Microsoft: no se usa", exe); return result; }

        int done = 0;
        using var gate = new SemaphoreSlim(2);
        var tasks = files.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).Select(async file =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var r = await _runner.RunAsync(exe, ["-Scan", "-ScanType", "3", "-File", file, "-DisableRemediation"], TimeSpan.FromMinutes(3), ct).ConfigureAwait(false);
                progress?.Report($"Microsoft Defender: {Interlocked.Increment(ref done)} de {files.Count}");
                return Parse(r.StdOut, r.ExitCode, file);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug("Defender no pudo analizar {File}: {Error}", file, ex.Message);
                return new List<ExternalDetection>();
            }
            finally { gate.Release(); }
        });
        foreach (var list in await Task.WhenAll(tasks).ConfigureAwait(false)) result.AddRange(list);
        _logger.LogInformation("Microsoft Defender analizó {Count} archivo(s): {Hits} amenaza(s)", files.Count, result.Count(d => d.Tool == "DEF"));
        return result;
    }

    /// <summary>
    /// Salida de MpCmdRun: "Scanning X found N threats." y por cada amenaza "Threat : Familia" + "file : ruta".
    /// Código de salida 2 = encontró amenazas.
    /// </summary>
    internal static List<ExternalDetection> Parse(string output, int exitCode, string file)
    {
        var list = new List<ExternalDetection>();
        if (exitCode != 2 && !output.Contains("found 1 threat", StringComparison.OrdinalIgnoreCase) &&
            !System.Text.RegularExpressions.Regex.IsMatch(output, @"found [1-9]\d* threats", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
        {
            // Analizado y limpio: sirve para contrastar con YARA (si los motores no coinciden, se baja la alarma).
            if (exitCode == 0 && output.Contains("found no threats", StringComparison.OrdinalIgnoreCase))
                list.Add(new ExternalDetection { Tool = "DEF-OK", Rule = "sin amenazas", TargetPath = file });
            return list;
        }
        foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(output, @"^\s*Threat\s*:\s*(?<t>.+?)\s*$", System.Text.RegularExpressions.RegexOptions.Multiline))
        {
            var threat = m.Groups["t"].Value;
            list.Add(new ExternalDetection { Tool = "DEF", Rule = threat, Family = threat, TargetPath = file, Level = "critical" });
        }
        if (list.Count == 0) // encontró algo pero no pudimos leer el nombre
            list.Add(new ExternalDetection { Tool = "DEF", Rule = "amenaza", Family = "una amenaza", TargetPath = file, Level = "critical" });
        return list;
    }
}
