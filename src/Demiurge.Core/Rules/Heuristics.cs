using System.Text.RegularExpressions;
using Demiurge.Core.Model;
using Demiurge.Core.Util;
using static Demiurge.Core.Rules.RuleContext;

namespace Demiurge.Core.Rules;

/// <summary>
/// Lógica de las heurísticas de 05_Heuristicas. Pesos, textos y parámetros vienen del YAML;
/// cada método evalúa la condición y emite findings sobre la entidad correspondiente.
/// </summary>
public static class Heuristics
{
    public static readonly IReadOnlyDictionary<string, Action<RuleContext, HeuristicDefinition>> All =
        new Dictionary<string, Action<RuleContext, HeuristicDefinition>>
        {
            ["H-01"] = H01_KnownMaliciousHash,
            ["H-02"] = H02_MaliciousInfrastructure,
            ["H-03"] = H03_Unsigned,
            ["H-04"] = H04_UserFolder,
            ["H-05"] = H05_Masquerading,
            ["H-06"] = H06_ParentChild,
            ["H-07"] = H07_Lolbin,
            ["H-08"] = H08_SuspiciousPersistence,
            ["H-09"] = H09_WmiPersistence,
            ["H-10"] = H10_Ifeo,
            ["H-11"] = H11_DefenderExclusions,
            ["H-12"] = H12_AntivirusOff,
            ["H-13"] = H13_Miner,
            ["H-14"] = H14_UnsignedOutbound,
            ["H-15"] = H15_NetworkConfig,
            ["H-16"] = H16_RootCertificate,
            ["H-17"] = H17_RemoteTool,
            ["H-18"] = H18_RiskyExtension,
            ["H-19"] = H19_BrowserHijack,
            ["H-20"] = H20_PushSpam,
            ["H-21"] = H21_SuspiciousDownload,
            ["H-22"] = H22_NewAdmin,
            ["H-23"] = H23_Ephemeral,
            ["H-24"] = H24_UnsignedDll,
            ["H-25"] = H25_Beaconing,
            ["H-26"] = H26_Yara,
            ["H-27"] = H27_Memory,
            ["H-28"] = H28_Driver,
            ["H-29"] = H29_LogCleared,
            ["H-30"] = H30_NewService,
            ["H-31"] = H31_Sigma,
            ["H-32"] = H32_DefenderConfirms,
            ["H-33"] = H33_DefenderHistory,
        };

    /// <summary>Binarios "activos": los que se ejecutan, arrancan solos o están cargados (no sólo descargados).</summary>
    private static HashSet<string> ActiveBinaryKeys(RuleContext ctx)
    {
        var set = new HashSet<string>();
        foreach (var p in ctx.Snapshot.Processes) if (p.BinaryKey is not null) set.Add(p.BinaryKey);
        foreach (var p in ctx.Snapshot.Persistence) if (p.BinaryKey is not null) set.Add(p.BinaryKey);
        foreach (var m in ctx.Snapshot.ModuleLoads) if (m.BinaryKey is not null) set.Add(m.BinaryKey);
        foreach (var d in ctx.Snapshot.Drivers) if (d.BinaryKey is not null) set.Add(d.BinaryKey);
        return set;
    }

    // ---------------------------------------------------------------- H-01
    private static void H01_KnownMaliciousHash(RuleContext ctx, HeuristicDefinition def)
    {
        foreach (var b in ctx.Snapshot.Binaries.Values)
        {
            var mal = b.Malicious;
            if (mal is null) continue;
            ctx.Emit(def, b, b.Key,
                new() { ["nombre"] = b.DisplayName, ["familia"] = mal.Family ?? $"malware (según {mal.Source})" },
                Raw(("path", b.Path), ("sha256", b.Sha256), ("source", mal.Source), ("family", mal.Family), ("detections", mal.Detections)));
        }
    }

    // ---------------------------------------------------------------- H-02
    private static void H02_MaliciousInfrastructure(RuleContext ctx, HeuristicDefinition def)
    {
        foreach (var c in ctx.Snapshot.Connections)
        {
            if (!IsPublicIp(c.RemoteAddress)) continue;
            var hit = ctx.Feeds.MatchIp(c.RemoteAddress, c.RemotePort);
            if (hit is null) continue;
            c.TiMatch = $"{hit.Source}: {hit.Family ?? hit.Category}";
            var binKey = ctx.BinaryKeyForPath(c.ProcessPath);
            var proc = ctx.ProcessesByPid.GetValueOrDefault(c.Pid);
            ctx.Emit(def, c, ctx.ScoringKeyFor(binKey, proc?.Key ?? c.Key),
                new() { ["nombre"] = c.ProcessName ?? $"PID {c.Pid}", ["destino"] = $"{c.RemoteAddress}:{c.RemotePort}", ["categoria"] = Describe(hit) },
                Raw(("pid", c.Pid), ("process", c.ProcessPath), ("remote", $"{c.RemoteAddress}:{c.RemotePort}"), ("feed", hit.Source), ("family", hit.Family), ("reference", hit.Reference)));
        }

        foreach (var q in ctx.Snapshot.DnsQueries)
        {
            var hit = ctx.Feeds.MatchDomain(q.Domain);
            if (hit is null) continue;
            q.TiMatch = $"{hit.Source}: {hit.Family ?? hit.Category}";
            string scoring = q.Key;
            string name = q.ProcessName ?? "Tu PC";
            if (q.Pid is int pid && ctx.ProcessesByPid.TryGetValue(pid, out var p))
            {
                scoring = ctx.ScoringKeyFor(p.BinaryKey, p.Key);
                name = p.Name;
            }
            ctx.Emit(def, q, scoring,
                new() { ["nombre"] = name, ["destino"] = q.Domain, ["categoria"] = Describe(hit) },
                Raw(("domain", q.Domain), ("pid", q.Pid), ("source", q.Source), ("feed", hit.Source), ("family", hit.Family)));
        }
    }

    private static string Describe(Intel.IocInfo hit) => hit.Family is null ? hit.Category : $"{hit.Category} ({hit.Family})";

    // ---------------------------------------------------------------- H-03
    private static void H03_Unsigned(RuleContext ctx, HeuristicDefinition def)
    {
        var active = ActiveBinaryKeys(ctx);
        foreach (var b in ctx.Snapshot.Binaries.Values)
        {
            if (!active.Contains(b.Key) || !ctx.IsUnsigned(b)) continue;
            ctx.Emit(def, b, b.Key, new() { ["nombre"] = b.DisplayName },
                Raw(("path", b.Path), ("signed", b.Signature!.IsSigned), ("valid", b.Signature.IsValid), ("signer", b.Signature.Signer), ("error", b.Signature.Error)));
        }
    }

    // ---------------------------------------------------------------- H-04
    private static void H04_UserFolder(RuleContext ctx, HeuristicDefinition def)
    {
        var active = ActiveBinaryKeys(ctx);
        foreach (var b in ctx.Snapshot.Binaries.Values)
        {
            if (!active.Contains(b.Key)) continue;
            var folder = PathClassifier.UserWritableFolder(b.Path);
            if (folder is null) continue;
            ctx.Emit(def, b, b.Key, new() { ["nombre"] = b.DisplayName, ["carpeta"] = folder }, Raw(("path", b.Path)));
        }
    }

    // ---------------------------------------------------------------- H-05
    private static void H05_Masquerading(RuleContext ctx, HeuristicDefinition def)
    {
        var official = def.Map("system_processes");
        var typos = def.List("typosquats").ToHashSet(StringComparer.OrdinalIgnoreCase);
        var win = PathClassifier.WindowsDir;
        var flagged = new HashSet<string>();

        void Check(string? path, IEntity entity, string? binKey)
        {
            if (string.IsNullOrEmpty(path)) return;
            var name = Path.GetFileName(path);
            bool hit = false;
            if (official.TryGetValue(name, out var dirs))
            {
                var dir = Path.GetDirectoryName(path)!.TrimEnd('\\') + "\\";
                hit = !dirs.Any(d => dir.Equals(Path.Combine(win, d).TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
                // WinSxS y servicing pueden tener copias legítimas firmadas por Microsoft.
                if (hit && ctx.Snapshot.GetBinary(binKey)?.Signature?.IsMicrosoft == true) hit = false;
            }
            else if (typos.Contains(name))
            {
                hit = true;
            }
            if (!hit) return;
            var key = binKey ?? entity.Key;
            if (!flagged.Add(key)) return;
            ctx.Emit(def, entity, key, new() { ["nombre"] = name }, Raw(("path", path), ("expected", official.TryGetValue(name, out var d2) ? string.Join(", ", d2.Select(x => Path.Combine(win, x))) : "(typosquatting)")));
        }

        foreach (var p in ctx.Snapshot.Processes) Check(p.Path, p, p.BinaryKey);
        foreach (var p in ctx.Snapshot.Persistence) Check(p.ResolvedPath, p, p.BinaryKey);
    }

    // ---------------------------------------------------------------- H-06
    internal static bool IsAnomalousParentChild(RuleContext ctx, HeuristicDefinition def, ProcessInfo child, out ProcessInfo? parent)
    {
        parent = null;
        if (!ctx.ProcessesByPid.TryGetValue(child.ParentPid, out var par)) return false;
        // Reutilización de PID: el padre tiene que haber nacido antes que el hijo.
        if (par.StartTime is not null && child.StartTime is not null && par.StartTime > child.StartTime) return false;
        parent = par;

        var parents = def.List("parents").ToHashSet(StringComparer.OrdinalIgnoreCase);
        var children = def.List("children").ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (parents.Contains(par.Name) && children.Contains(child.Name))
        {
            foreach (var pair in def.List("allowed_pairs"))
            {
                var parts = pair.Split('>', '?');
                if (parts.Length >= 2 && par.Name.Equals(parts[0], StringComparison.OrdinalIgnoreCase) && child.Name.Equals(parts[1], StringComparison.OrdinalIgnoreCase) &&
                    (parts.Length < 3 || (child.CommandLine ?? "").Contains(parts[2], StringComparison.OrdinalIgnoreCase)))
                    return false;
            }
            return true;
        }
        // svchost.exe siempre lo lanza services.exe.
        if (child.Name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase) &&
            !par.Name.Equals("services.exe", StringComparison.OrdinalIgnoreCase) &&
            !par.Name.Equals("MsMpEng.exe", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static void H06_ParentChild(RuleContext ctx, HeuristicDefinition def)
    {
        foreach (var child in ctx.Snapshot.Processes)
        {
            if (!IsAnomalousParentChild(ctx, def, child, out var parent) || parent is null) continue;
            ctx.Emit(def, child, child.Key,
                new() { ["padre"] = parent.Name, ["hijo"] = child.Name },
                Raw(("parent", parent.Path ?? parent.Name), ("parentPid", parent.Pid), ("child", child.Path ?? child.Name), ("pid", child.Pid), ("cmdline", child.CommandLine)));
        }
    }

    // ---------------------------------------------------------------- H-07
    private static readonly Dictionary<string, Regex> RegexCache = new();

    private static Regex Rx(string pattern)
    {
        lock (RegexCache)
        {
            if (!RegexCache.TryGetValue(pattern, out var r))
                RegexCache[pattern] = r = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));
            return r;
        }
    }

    internal static string? MatchLolbin(HeuristicDefinition def, string? exeName, string? commandLine, IReadOnlyDictionary<string, HashSet<string>>? lolbas = null)
    {
        if (exeName is null || string.IsNullOrEmpty(commandLine)) return null;
        var patterns = def.Map("patterns");
        if (!patterns.TryGetValue(exeName, out var list)) return null;
        foreach (var p in list)
        {
            try
            {
                if (Rx(p).IsMatch(commandLine)) return p;
            }
            catch (RegexMatchTimeoutException)
            {
                // patrón patológico: ignorar
            }
        }
        return null;
    }

    private static void H07_Lolbin(RuleContext ctx, HeuristicDefinition def)
    {
        foreach (var p in ctx.Snapshot.Processes)
        {
            var hit = MatchLolbin(def, p.Name, p.CommandLine);
            if (hit is null) continue;
            ctx.Emit(def, p, p.Key, new() { ["nombre"] = p.Name },
                Raw(("pid", p.Pid), ("cmdline", p.CommandLine), ("pattern", hit), ("lolbas", ctx.Feeds.Lolbas.TryGetValue(p.Name, out var cats) ? string.Join(", ", cats) : null)));
        }
        // También en comandos de persistencia (tarea que corre "powershell -enc ...").
        foreach (var item in ctx.Snapshot.Persistence)
        {
            var exe = Path.GetFileName(CommandLineResolver.Resolve(item.Command).Executable ?? "");
            var hit = MatchLolbin(def, exe, item.Command);
            if (hit is null) continue;
            ctx.Emit(def, item, item.Key, new() { ["nombre"] = exe }, Raw(("location", item.Location), ("command", item.Command), ("pattern", hit)));
        }
    }

    // ---------------------------------------------------------------- H-08
    private static void H08_SuspiciousPersistence(RuleContext ctx, HeuristicDefinition def)
    {
        bool signedUserFolderCounts = def.Params.TryGetValue("signed_user_folder_counts", out var v) && bool.TryParse(v?.ToString(), out var b0) && b0;
        foreach (var item in ctx.Snapshot.Persistence)
        {
            var b = ctx.Snapshot.GetBinary(item.BinaryKey);
            if (b is null || !b.Exists) continue;
            if (ctx.IsHardAllowlisted(b)) continue;
            // Tarea de Microsoft con binario firmado ya quedó filtrada arriba; las de KB conocida bajan ruido.
            if (item.Type == PersistenceType.Task && ctx.Kb.MatchTask(item.Location) is { Risk: "benign" } && b.Signature?.IsValid == true) continue;
            bool unsigned = ctx.IsUnsigned(b);
            var folder = PathClassifier.UserWritableFolder(b.Path);
            if (!unsigned && folder is null) continue;
            // Calibración: apps firmadas que se instalan por usuario (Notion, Discord, Battle.net...) no suman por arrancar solas.
            if (!unsigned && !signedUserFolderCounts && b.Signature?.IsValid == true) continue;
            ctx.Emit(def, item, b.Key, new() { ["nombre"] = b.DisplayName },
                Raw(("type", item.Type.ToString()), ("location", item.Location), ("name", item.Name), ("command", item.Command),
                    ("unsigned", unsigned), ("folder", folder), ("hidden", item.Hidden)));
        }
    }

    // ---------------------------------------------------------------- H-09
    private static void H09_WmiPersistence(RuleContext ctx, HeuristicDefinition def)
    {
        var allowed = def.List("allowed_consumers").ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var item in ctx.Snapshot.Persistence.Where(p => p.Type == PersistenceType.Wmi))
        {
            if (allowed.Contains(item.Name)) continue;
            ctx.Emit(def, item, ctx.ScoringKeyFor(item.BinaryKey, item.Key), new() { ["nombre"] = item.Name },
                Raw(("consumer", item.Extra.GetValueOrDefault("consumerClass")), ("name", item.Name), ("command", item.Command),
                    ("filter", item.Extra.GetValueOrDefault("filterQuery"))));
        }
    }

    // ---------------------------------------------------------------- H-10
    private static void H10_Ifeo(RuleContext ctx, HeuristicDefinition def)
    {
        var accessibility = def.List("accessibility").ToHashSet(StringComparer.OrdinalIgnoreCase);
        var allowed = def.List("allowed_debuggers");
        foreach (var item in ctx.Snapshot.Persistence.Where(p => p.Type == PersistenceType.Ifeo))
        {
            var target = item.Extra.GetValueOrDefault("target") ?? item.Name;
            var debuggerName = Path.GetFileName(item.ResolvedPath ?? item.Command ?? "");
            if (allowed.Any(a => debuggerName.Equals(a, StringComparison.OrdinalIgnoreCase))) continue;
            bool isAccessibility = accessibility.Contains(target);
            bool isSystemBinary = File.Exists(Path.Combine(PathClassifier.System32Dir, target));
            if (!isAccessibility && !isSystemBinary) continue;
            ctx.Emit(def, item, item.Key, new() { ["objetivo"] = target, ["nombre"] = debuggerName },
                Raw(("target", target), ("debugger", item.Command), ("mechanism", item.Extra.GetValueOrDefault("mechanism")), ("accessibility", isAccessibility)),
                weightOverride: isAccessibility ? null : Math.Max(def.Weight - 20, 30));
        }
    }

    // ---------------------------------------------------------------- H-11
    private static void H11_DefenderExclusions(RuleContext ctx, HeuristicDefinition def)
    {
        var broad = def.List("broad").Select(b => Environment.ExpandEnvironmentVariables(b).TrimEnd('\\')).ToList();
        foreach (var s in ctx.Snapshot.Settings.Where(s => s.Name.StartsWith("defender_exclusion_", StringComparison.Ordinal)))
        {
            var value = s.Value ?? "";
            var expanded = Environment.ExpandEnvironmentVariables(value).TrimEnd('\\');
            bool isBroad = broad.Any(b => b.Equals(expanded, StringComparison.OrdinalIgnoreCase));
            bool userFolder = PathClassifier.UserWritableFolder(expanded.EndsWith('\\') ? expanded : expanded + "\\") is not null;
            bool unknownProcess = false;
            if (s.Name == "defender_exclusion_process")
            {
                var b = ctx.Snapshot.Binaries.Values.FirstOrDefault(x => x.Path.Equals(expanded, StringComparison.OrdinalIgnoreCase) || x.DisplayName.Equals(Path.GetFileName(expanded), StringComparison.OrdinalIgnoreCase));
                unknownProcess = b is null || !ctx.IsHardAllowlisted(b);
            }
            if (s.Name == "defender_exclusion_extension") isBroad = isBroad || value.Trim('.').ToLowerInvariant() is "exe" or "dll" or "ps1" or "bat" or "vbs" or "js" or "scr";
            if (!isBroad && !userFolder && !unknownProcess) continue;
            ctx.Emit(def, s, s.Key, new() { ["ruta"] = value },
                Raw(("type", s.Name), ("value", value), ("broad", isBroad), ("userFolder", userFolder)));
        }
    }

    // ---------------------------------------------------------------- H-12
    private static void H12_AntivirusOff(RuleContext ctx, HeuristicDefinition def)
    {
        var d = ctx.Snapshot.Defender;
        bool otherActive = d.OtherAntivirus.Any(a => !a.EndsWith("(inactivo)"));
        if (d.RealTimeProtectionEnabled != false || otherActive) return;
        var s = ctx.Snapshot.Settings.FirstOrDefault(x => x.Name == "defender_rtp") ?? new SystemSetting { Name = "defender_rtp", Value = "False" };
        ctx.Emit(def, s, s.Key, new(), Raw(("antivirusEnabled", d.AntivirusEnabled), ("realTime", d.RealTimeProtectionEnabled), ("otherAv", string.Join(", ", d.OtherAntivirus))));
    }

    // ---------------------------------------------------------------- H-13
    private static void H13_Miner(RuleContext ctx, HeuristicDefinition def)
    {
        int cpu = def.Int("cpu_percent", 40);
        int gpu = def.Int("gpu_percent", 50);
        var minerNames = def.List("miner_names").ToHashSet(StringComparer.OrdinalIgnoreCase);
        var minerCmd = def.List("miner_cmdline");
        foreach (var p in ctx.Snapshot.Processes.Where(p => !p.Ephemeral))
        {
            var b = ctx.Snapshot.GetBinary(p.BinaryKey);
            bool minerLike = minerNames.Contains(p.Name) || minerCmd.Any(rx => p.CommandLine is not null && Rx(rx).IsMatch(p.CommandLine));
            bool highCpu = p.CpuPercent >= cpu;
            bool highGpu = p.GpuPercent >= gpu;
            if (!minerLike && !highCpu && !highGpu) continue;
            bool suspiciousBinary = b is not null && !ctx.IsHardAllowlisted(b) && (ctx.IsUnsigned(b) || PathClassifier.UserWritableFolder(b.Path) is not null);
            if (!minerLike && !suspiciousBinary) continue;
            var recurso = highGpu && highCpu ? "procesador y placa de video" : highGpu ? "placa de video" : "procesador";
            ctx.Emit(def, p, ctx.ScoringKeyFor(p.BinaryKey, p.Key), new() { ["nombre"] = p.Name, ["recurso"] = recurso },
                Raw(("pid", p.Pid), ("cpu", p.CpuPercent), ("gpu", p.GpuPercent), ("minerLike", minerLike), ("cmdline", p.CommandLine)));
        }
    }

    // ---------------------------------------------------------------- H-14
    private static void H14_UnsignedOutbound(RuleContext ctx, HeuristicDefinition def)
    {
        var done = new HashSet<string>();
        foreach (var c in ctx.Snapshot.Connections)
        {
            if (c.IsListening || !IsPublicIp(c.RemoteAddress)) continue;
            var binKey = ctx.BinaryKeyForPath(c.ProcessPath);
            var b = ctx.Snapshot.GetBinary(binKey);
            if (b is null || !ctx.IsUnsigned(b) || !done.Add(b.Key)) continue;
            ctx.Emit(def, c, b.Key, new() { ["nombre"] = b.DisplayName, ["destino"] = $"{c.RemoteAddress}:{c.RemotePort}" },
                Raw(("pid", c.Pid), ("remote", $"{c.RemoteAddress}:{c.RemotePort}"), ("state", c.State)));
        }
    }

    // ---------------------------------------------------------------- H-15
    private static void H15_NetworkConfig(RuleContext ctx, HeuristicDefinition def)
    {
        var sensitive = def.List("sensitive_domains");
        var knownDns = def.List("known_dns").ToHashSet(StringComparer.OrdinalIgnoreCase);
        var allowedProxies = def.List("allowed_proxies").ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var s in ctx.Snapshot.Settings)
        {
            switch (s.Name)
            {
                case "hosts":
                {
                    var parts = (s.Value ?? "").Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) continue;
                    var hosts = parts.Skip(1).Where(h => sensitive.Any(d => h.Contains(d, StringComparison.OrdinalIgnoreCase))).ToList();
                    if (hosts.Count == 0) continue;
                    var blocked = parts[0] is "0.0.0.0" or "127.0.0.1" or "::1";
                    ctx.Emit(def, s, "hosts", new() { ["detalle"] = blocked ? $"se bloqueó el acceso a {string.Join(", ", hosts)}" : $"{string.Join(", ", hosts)} se desvía a {parts[0]}" },
                        Raw(("entry", s.Value), ("file", @"C:\Windows\System32\drivers\etc\hosts")));
                    break;
                }
                case "dns":
                {
                    if (s.Source != "static" || !IsPublicIp(s.Value) || knownDns.Contains(s.Value ?? "")) continue;
                    ctx.Emit(def, s, "network_dns", new() { ["detalle"] = $"servidor DNS fijado a mano: {s.Value}" }, Raw(("dns", s.Value), ("adapter", s.Detail)));
                    break;
                }
                case "proxy":
                {
                    var v = s.Value ?? "";
                    if (allowedProxies.Contains(v)) continue;
                    bool loopback = v.Contains("127.0.0.1") || v.Contains("localhost", StringComparison.OrdinalIgnoreCase) || v.Contains("[::1]");
                    if (loopback) continue; // VPNs, antivirus y herramientas de desarrollo usan proxies locales.
                    ctx.Emit(def, s, "network_proxy", new() { ["detalle"] = $"proxy {v}" }, Raw(("proxy", v), ("where", s.Detail)));
                    break;
                }
                case "proxy_pac":
                    ctx.Emit(def, s, "network_proxy", new() { ["detalle"] = $"script de proxy {s.Value}" }, Raw(("pac", s.Value), ("where", s.Detail)));
                    break;
            }
        }
    }

    // ---------------------------------------------------------------- H-16
    private static void H16_RootCertificate(RuleContext ctx, HeuristicDefinition def)
    {
        var authroot = ctx.Feeds.AuthRootThumbprints;
        if (authroot.Count == 0) return; // sin lista de referencia no podemos distinguir
        foreach (var c in ctx.Snapshot.Certificates)
        {
            c.InAuthRoot = authroot.Contains(c.Thumbprint);
            if (c.InAuthRoot == true) continue;
            var kb = ctx.Kb.MatchCertificate(c.Subject) ?? ctx.Kb.MatchCertificate(c.Issuer);
            if (kb?.Risk == "benign" && kb.RequirementsMet(ctx.Snapshot.Software)) continue;
            ctx.Emit(def, c, "cert:" + c.Thumbprint.ToLowerInvariant(), new() { ["nombre"] = c.Subject },
                Raw(("subject", c.Subject), ("issuer", c.Issuer), ("thumbprint", c.Thumbprint), ("store", c.Store), ("notAfter", c.NotAfter.ToString("yyyy-MM-dd")), ("kb", kb?.Title)),
                weightOverride: kb?.Risk == "question" ? def.Weight / 2 : null);
        }
    }

    // ---------------------------------------------------------------- H-17
    private static void H17_RemoteTool(RuleContext ctx, HeuristicDefinition def)
    {
        var flagged = new HashSet<string>();
        foreach (var sw in ctx.Snapshot.Software)
        {
            var kb = ctx.Kb.MatchSoftware(sw);
            if (kb is null) continue;
            sw.KbId = kb.Id;
            sw.Category = kb.Category is "remote_tool" or "pup" ? kb.Category : sw.Category;
            if (kb.Category != "remote_tool" || kb.Risk != "question" || !flagged.Add(kb.Id)) continue;
            EmitRemote(ctx, def, sw, kb.Title, sw.Key);
        }
        // Versiones portables: no aparecen en "Programas instalados" pero corren.
        foreach (var p in ctx.Snapshot.Processes)
        {
            var b = ctx.Snapshot.GetBinary(p.BinaryKey);
            var kb = ctx.Kb.MatchBinary(b)?.Entry;
            if (kb is null || kb.Category != "remote_tool" || kb.Risk != "question" || !flagged.Add(kb.Id)) continue;
            EmitRemote(ctx, def, p, kb.Title, "remote:" + kb.Id);
        }
    }

    private static void EmitRemote(RuleContext ctx, HeuristicDefinition def, IEntity entity, string title, string scoringKey)
    {
        int weight = def.Weight;
        string? answer = null;
        if (def.Question is not null && ctx.Answers.TryGetValue($"{scoringKey}|{def.Question.Id}", out var a))
        {
            answer = a.Answer;
            weight = def.Question.Options.FirstOrDefault(o => o.Value == a.Answer)?.Weight ?? weight;
        }
        var f = ctx.Emit(def, entity, scoringKey, new() { ["nombre"] = title }, Raw(("program", title), ("answer", answer)), weight);
        if (answer is not null) f.Question = null; // ya respondida
    }

    // ---------------------------------------------------------------- H-18
    private static void H18_RiskyExtension(RuleContext ctx, HeuristicDefinition def)
    {
        var broad = def.List("broad_permissions").ToHashSet(StringComparer.OrdinalIgnoreCase);
        int storeMin = def.Int("store_min_broad", 3);
        foreach (var e in ctx.Snapshot.Extensions)
        {
            if (!e.Enabled) continue;
            var kb = ctx.Kb.MatchExtension(e.Id);
            if (kb?.Risk == "benign") continue;
            var broadPerms = e.Permissions.Where(p => broad.Contains(p) || p is "<all_urls>" || p.StartsWith("*://*/") || p.StartsWith("http://*/") || p.StartsWith("https://*/")).Distinct().ToList();
            string? motivo = null;
            if (e.Origin == "sideload") motivo = " y no se instaló desde la tienda oficial";
            else if (e.Origin == "policy") motivo = " y fue forzada por una política del sistema";
            else if (e.Origin != "store" && broadPerms.Count > 0) motivo = " y no sabemos de dónde salió";
            else if (broadPerms.Count >= storeMin) motivo = "";
            if (motivo is null) continue;
            if (broadPerms.Count == 0 && e.Origin == "store") continue;
            ctx.Emit(def, e, e.Key, new() { ["nombre"] = e.Name, ["navegador"] = e.Browser, ["motivo"] = motivo },
                Raw(("id", e.Id), ("browser", e.Browser), ("profile", e.Profile), ("origin", e.Origin), ("permissions", broadPerms), ("updateUrl", e.UpdateUrl)));
        }
    }

    // ---------------------------------------------------------------- H-19
    private static void H19_BrowserHijack(RuleContext ctx, HeuristicDefinition def)
    {
        var search = def.List("standard_search");
        var home = def.List("standard_home");
        foreach (var s in ctx.Snapshot.BrowserSettings)
        {
            string? label = s.Setting switch
            {
                "search_engine" when !Matches(s.Value, search) && s.Browser != "Firefox" => "buscador predeterminado",
                "search_engine" when s.Browser == "Firefox" && !Matches(s.Value, ["google", "bing", "duckduckgo", "ecosia", "wikipedia", "amazon", "ebay", "qwant", "startpage", "yahoo", "perplexity", "mercadolibre"]) => "buscador predeterminado",
                "homepage" when !Matches(s.Value, home) => "página de inicio",
                "startup_url" when !Matches(s.Value, home) => "página que se abre al iniciar",
                "policy" when IsHijackPolicy(s.Value, search, home) => "configuración forzada por política",
                "proxy" => "proxy del navegador",
                _ => null,
            };
            if (label is null) continue;
            ctx.Emit(def, s, $"browser:{s.Browser}|{s.User}|{s.Profile}|{s.Setting}".ToLowerInvariant(),
                new() { ["ajuste"] = label, ["navegador"] = s.Browser, ["valor"] = Shorten(s.Value) },
                Raw(("browser", s.Browser), ("profile", s.Profile), ("user", s.User), ("setting", s.Setting), ("value", s.Value)));
        }
    }

    private static bool IsHijackPolicy(string value, List<string> search, List<string> home)
    {
        var kv = value.Split('=', 2);
        if (kv.Length < 2) return false;
        return kv[0] switch
        {
            "DefaultSearchProviderSearchURL" => !Matches(kv[1], search),
            "HomepageLocation" or "NewTabPageLocation" or "RestoreOnStartupURLs" => !Matches(kv[1], home),
            "ExtensionInstallForcelist" => !kv[1].Contains("clients2.google.com") && !kv[1].Contains("edge.microsoft.com"),
            "ProxyServer" or "ProxyPacUrl" => true,
            _ => false,
        };
    }

    private static bool Matches(string value, IEnumerable<string> allowed)
    {
        var host = Uri.TryCreate(value, UriKind.Absolute, out var u) ? u.Host + u.AbsolutePath : value;
        if (value.StartsWith("{google:baseURL}", StringComparison.OrdinalIgnoreCase)) return true;
        return allowed.Any(a => host.Contains(a, StringComparison.OrdinalIgnoreCase) || value.StartsWith(a, StringComparison.OrdinalIgnoreCase));
    }

    private static string Shorten(string s) => s.Length > 80 ? s[..77] + "…" : s;

    // ---------------------------------------------------------------- H-20
    private static void H20_PushSpam(RuleContext ctx, HeuristicDefinition def)
    {
        var allowed = def.List("allowed");
        int minUnknown = def.Int("min_unknown", 1);
        foreach (var group in ctx.Snapshot.BrowserSettings.Where(s => s.Setting == "notifications").GroupBy(s => (s.Browser, s.User, s.Profile)))
        {
            var unknown = group.Where(s => !allowed.Any(a => s.Value.Contains(a, StringComparison.OrdinalIgnoreCase))).ToList();
            if (unknown.Count < minUnknown) continue;
            var first = unknown[0];
            ctx.Emit(def, first, $"notifications:{group.Key.Browser}|{group.Key.User}|{group.Key.Profile}".ToLowerInvariant(),
                new() { ["sitios"] = string.Join(", ", unknown.Take(3).Select(u => Uri.TryCreate(u.Value, UriKind.Absolute, out var x) ? x.Host : u.Value)) + (unknown.Count > 3 ? $" y {unknown.Count - 3} más" : "") },
                Raw(("browser", group.Key.Browser), ("profile", group.Key.Profile), ("sites", unknown.Select(u => u.Value).ToList())));
        }
    }

    // ---------------------------------------------------------------- H-21
    private static void H21_SuspiciousDownload(RuleContext ctx, HeuristicDefinition def)
    {
        foreach (var f in ctx.Snapshot.RecentFiles)
        {
            string? motivo = null;
            if (f.DoubleExtension) motivo = "parece un documento pero en realidad es un programa";
            Intel.IocInfo? hit = null;
            foreach (var url in new[] { f.HostUrl, f.ReferrerUrl })
            {
                if (url is null) continue;
                // URL exacta primero (sirve también para hostings compartidos), después el dominio.
                hit ??= ctx.Feeds.MatchUrl(url);
                if (Uri.TryCreate(url, UriKind.Absolute, out var u)) hit ??= ctx.Feeds.MatchDomain(u.Host);
            }
            if (hit is not null)
                motivo = motivo is null ? $"se descargó de un sitio reportado por {hit.Category}" : motivo + $" y se descargó de un sitio reportado por {hit.Category}";
            if (motivo is null) continue;
            ctx.Emit(def, f, f.BinaryKey ?? f.Key, new() { ["nombre"] = f.DisplayName, ["motivo"] = motivo },
                Raw(("path", f.Path), ("hostUrl", f.HostUrl), ("referrer", f.ReferrerUrl), ("zone", f.ZoneId), ("feed", hit?.Source)));
        }
    }

    // ---------------------------------------------------------------- H-22
    private static void H22_NewAdmin(RuleContext ctx, HeuristicDefinition def)
    {
        int days = def.Int("recent_days", 30);
        var previous = ctx.Previous?.Accounts.Select(a => a.Key).ToHashSet();
        var recentEvents = ctx.Snapshot.Events.Where(e => e.EventId is 4720 or 4732).ToList();
        foreach (var a in ctx.Snapshot.Accounts.Where(a => a.IsAdmin && a.Enabled && !a.BuiltIn))
        {
            bool recent = a.Created is not null && a.Created > DateTimeOffset.Now.AddDays(-days);
            bool newSinceLastScan = previous is not null && !previous.Contains(a.Key);
            bool eventSeen = recentEvents.Any(e => e.Data.Values.Any(v => v.Equals(a.Name, StringComparison.OrdinalIgnoreCase) || (a.Sid is not null && v.Equals(a.Sid, StringComparison.OrdinalIgnoreCase))));
            // Primer escaneo: sólo marcamos cuentas creadas muy recientemente (la PC nueva tiene todas "recientes").
            if (!newSinceLastScan && !eventSeen && !(recent && previous is not null)) continue;

            int weight = def.Weight;
            string? answer = null;
            if (def.Question is not null && ctx.Answers.TryGetValue($"{a.Key}|{def.Question.Id}", out var ans))
            {
                answer = ans.Answer;
                weight = def.Question.Options.FirstOrDefault(o => o.Value == ans.Answer)?.Weight ?? weight;
            }
            var f = ctx.Emit(def, a, a.Key, new() { ["nombre"] = a.Name },
                Raw(("account", a.Name), ("sid", a.Sid), ("created", a.Created?.ToString("yyyy-MM-dd")), ("newSinceLastScan", newSinceLastScan), ("event", eventSeen), ("answer", answer)), weight);
            if (answer is not null) f.Question = null;
        }
    }

    // ---------------------------------------------------------------- H-23
    private static void H23_Ephemeral(RuleContext ctx, HeuristicDefinition def)
    {
        var h06 = ctx.Rules["H-06"];
        var h07 = ctx.Rules["H-07"];
        int maxSeconds = def.Int("max_seconds", 10);
        foreach (var p in ctx.Snapshot.Processes.Where(p => p.Ephemeral && p.EndTime is not null && p.StartTime is not null))
        {
            var life = p.EndTime!.Value - p.StartTime!.Value;
            if (life.TotalSeconds > maxSeconds) continue;
            bool parentChild = h06 is not null && IsAnomalousParentChild(ctx, h06, p, out _);
            bool lolbin = h07 is not null && MatchLolbin(h07, p.Name, p.CommandLine) is not null;
            if (!parentChild && !lolbin) continue;
            ctx.Emit(def, p, p.Key, new() { ["nombre"] = p.Name, ["duracion"] = life.TotalMilliseconds < 1000 ? $"{life.TotalMilliseconds:0} ms" : $"{life.TotalSeconds:0.#} s" },
                Raw(("pid", p.Pid), ("ppid", p.ParentPid), ("cmdline", p.CommandLine), ("parentChild", parentChild), ("lolbin", lolbin)));
        }
    }

    // ---------------------------------------------------------------- H-24
    private static void H24_UnsignedDll(RuleContext ctx, HeuristicDefinition def)
    {
        foreach (var m in ctx.Snapshot.ModuleLoads)
        {
            var dll = ctx.Snapshot.GetBinary(m.BinaryKey);
            if (dll is null || !ctx.IsUnsigned(dll) || ctx.IsHardAllowlisted(dll)) continue;
            if (PathClassifier.UserWritableFolder(dll.Path) is null) continue;
            var proc = ctx.ProcessesByPid.GetValueOrDefault(m.Pid);
            var host = ctx.Snapshot.GetBinary(proc?.BinaryKey);
            if (host?.Signature?.IsValid != true) continue;
            // Apps instaladas por usuario (Discord, Teams...) cargan sus propias DLLs desde AppData: mismo directorio = normal.
            if (proc?.Path is not null && Path.GetDirectoryName(dll.Path)!.StartsWith(Path.GetDirectoryName(proc.Path)!, StringComparison.OrdinalIgnoreCase)) continue;
            ctx.Emit(def, m, dll.Key, new() { ["nombre"] = dll.DisplayName, ["proceso"] = proc?.Name ?? m.ProcessName ?? "?" },
                Raw(("dll", dll.Path), ("process", proc?.Path), ("pid", m.Pid)));
        }
    }

    // ---------------------------------------------------------------- H-25
    /// <summary>
    /// Sin telemetría en segundo plano, el beaconing se aproxima comparando escaneos cercanos: un programa sin firma
    /// que sigue conectado al mismo destino en dos escaneos separados por un rato es lo que hace un RAT o un
    /// stealer que "reporta" a su servidor.
    /// </summary>
    private static void H25_Beaconing(RuleContext ctx, HeuristicDefinition def)
    {
        var prev = ctx.Previous;
        if (prev is null) return;
        var gap = ctx.Snapshot.Scan.Started - prev.Scan.Started;
        if (gap < TimeSpan.FromMinutes(def.Int("min_gap_minutes", 15)) || gap > TimeSpan.FromHours(def.Int("max_gap_hours", 48))) return;

        static string Key(ConnectionInfo c) => $"{(c.ProcessPath ?? c.ProcessName ?? "").ToLowerInvariant()}|{c.RemoteAddress}|{c.RemotePort}";
        var before = prev.Connections
            .Where(c => !c.IsListening && IsPublicIp(c.RemoteAddress))
            .Select(Key).ToHashSet();

        var done = new HashSet<string>();
        foreach (var c in ctx.Snapshot.Connections)
        {
            if (c.IsListening || !IsPublicIp(c.RemoteAddress) || !before.Contains(Key(c)) || !done.Add(Key(c))) continue;
            var b = ctx.Snapshot.GetBinary(ctx.BinaryKeyForPath(c.ProcessPath));
            // Software firmado y conocido (telemetría, chats, updaters) también mantiene conexiones largas.
            if (b is null || ctx.IsHardAllowlisted(b) || b.Signature?.IsValid == true) continue;
            ctx.Emit(def, c, b.Key,
                new()
                {
                    ["nombre"] = b.DisplayName,
                    ["destino"] = $"{c.RemoteAddress}:{c.RemotePort}",
                    ["intervalo"] = gap.TotalHours >= 2 ? $"{gap.TotalHours:0} horas" : $"{gap.TotalMinutes:0} minutos",
                },
                Raw(("remote", $"{c.RemoteAddress}:{c.RemotePort}"), ("process", c.ProcessPath), ("previousScan", prev.Scan.Started.ToString("O")), ("gapMinutes", Math.Round(gap.TotalMinutes))));
        }
    }

    // ---------------------------------------------------------------- H-26 / H-27 / H-31 (herramientas externas)
    /// <summary>
    /// YARA, contrastado con los otros motores:
    ///  - regla de baja confianza (score de YARA Forge &lt; 70, o familias de reglas pensadas para memoria como CAPE_) → pesa menos;
    ///  - Defender analizó el mismo archivo y no encontró nada → pesa mucho menos y se avisa que puede ser falso positivo;
    ///  - además tiene firma digital válida → queda informativo.
    /// </summary>
    private static void H26_Yara(RuleContext ctx, HeuristicDefinition def)
    {
        var defenderClean = ctx.Snapshot.ExternalDetections.Where(d => d.Tool == "DEF-OK" && d.TargetPath is not null)
            .Select(d => d.TargetPath!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var lowPrefixes = def.List("low_confidence_prefixes");

        int? Weight(ExternalDetection d)
        {
            bool lowRule = (int.TryParse(d.Level, out var score) && score < def.Int("min_confident_score", 70)) ||
                           lowPrefixes.Any(p => d.Rule.StartsWith(p, StringComparison.OrdinalIgnoreCase));
            bool clean = d.TargetPath is not null && defenderClean.Contains(d.TargetPath);
            bool signed = ctx.Snapshot.GetBinary(ctx.BinaryKeyForPath(d.TargetPath))?.Signature?.IsValid == true;
            if (clean && signed) return def.Int("contradicted_signed_weight", 10);
            if (clean) return def.Int("contradicted_weight", 25);
            if (lowRule || signed) return def.Int("low_confidence_weight", 35);
            return null;
        }

        string? Note(ExternalDetection d) => d.TargetPath is not null && defenderClean.Contains(d.TargetPath)
            ? " Microsoft Defender lo analizó y no encontró amenazas, así que puede ser un falso positivo."
            : null;

        EmitExternal(ctx, def, "EXT-01", Weight, Note);
    }

    /// <summary>Microsoft Defender analizó el archivo a pedido de Demiurge y confirmó que es malware.</summary>
    private static void H32_DefenderConfirms(RuleContext ctx, HeuristicDefinition def) => EmitExternal(ctx, def, "DEF");

    /// <summary>
    /// Historial de Defender: amenazas detectadas en los últimos días cuyo archivo SIGUE en la PC (no se pudo
    /// eliminar, o el usuario lo permitió). Las que ya se resolvieron se muestran aparte, sin alarmar.
    /// </summary>
    private static void H33_DefenderHistory(RuleContext ctx, HeuristicDefinition def)
    {
        int days = def.Int("days", 30);
        var since = DateTimeOffset.Now.AddDays(-days);
        foreach (var det in ctx.Snapshot.Defender.Detections.Where(d => d.Time is null || d.Time >= since))
        {
            foreach (var path in DefenderFilePaths(det))
            {
                if (!File.Exists(path)) continue;
                var binKey = ctx.BinaryKeyForPath(path);
                var bin = ctx.Snapshot.GetBinary(binKey) ?? new BinaryInfo { Path = path };
                ctx.Emit(def, bin, bin.Key,
                    new() { ["nombre"] = Path.GetFileName(path), ["familia"] = det.ThreatName, ["fecha"] = det.Time?.ToLocalTime().ToString("dd/MM/yyyy") ?? "?" },
                    Raw(("threat", det.ThreatName), ("path", path), ("detected", det.Time?.ToString("O")), ("actionSuccess", det.Action)));
            }
        }
    }

    /// <summary>Recursos de una detección de Defender: "file:_C:\ruta\x.exe" (a veces con "->" para archivos dentro de zips).</summary>
    internal static IEnumerable<string> DefenderFilePaths(DefenderDetection det)
    {
        foreach (var r in det.Resources)
        {
            var i = r.IndexOf("file:_", StringComparison.OrdinalIgnoreCase);
            if (i < 0) continue;
            var path = r[(i + 6)..];
            var arrow = path.IndexOf("->", StringComparison.Ordinal);
            if (arrow > 0) path = path[..arrow];
            yield return path.Trim();
        }
    }
    private static void H27_Memory(RuleContext ctx, HeuristicDefinition def) => EmitExternal(ctx, def, "EXT-02");
    private static void H31_Sigma(RuleContext ctx, HeuristicDefinition def) => EmitExternal(ctx, def, "EXT-03");

    private static void EmitExternal(RuleContext ctx, HeuristicDefinition def, string tool, Func<ExternalDetection, int?>? weight = null, Func<ExternalDetection, string?>? note = null)
    {
        foreach (var d in ctx.Snapshot.ExternalDetections.Where(x => x.Tool == tool))
        {
            if (tool == "EXT-03" && d.Level is not ("high" or "critical")) continue;
            IEntity entity;
            string scoring;
            ProcessInfo? proc = d.Pid is int pid ? ctx.ProcessesByPid.GetValueOrDefault(pid) : null;
            var binKey = proc?.BinaryKey ?? ctx.BinaryKeyForPath(d.TargetPath);
            var bin = ctx.Snapshot.GetBinary(binKey);
            if (proc is not null) { entity = proc; scoring = ctx.ScoringKeyFor(binKey, proc.Key); }
            else if (bin is not null) { entity = bin; scoring = bin.Key; }
            else
            {
                var ev = new EventInfo { Log = tool, EventId = 0, Message = d.Rule, Source = tool, Timestamp = DateTimeOffset.Now, RecordId = Math.Abs((d.Rule + d.TargetPath).GetHashCode()) };
                entity = ev;
                scoring = $"{tool}:{d.Rule}".ToLowerInvariant();
            }
            var f = ctx.Emit(def, entity, scoring,
                new() { ["nombre"] = proc?.Name ?? bin?.DisplayName ?? Path.GetFileName(d.TargetPath ?? "") , ["familia"] = d.Family ?? d.Rule, ["regla"] = d.Rule, ["detalle"] = d.Data.GetValueOrDefault("detail") ?? d.Rule },
                Raw(("tool", tool), ("rule", d.Rule), ("family", d.Family), ("level", d.Level), ("target", d.TargetPath), ("pid", d.Pid),
                    ("author", d.Data.GetValueOrDefault("author")), ("reference", d.Data.GetValueOrDefault("reference"))),
                weight?.Invoke(d));
            if (note?.Invoke(d) is { } extra)
            {
                f.Explanation += extra;
                f.RecommendedAction = "Si reconocés el programa, marcalo como \"Lo reconozco\". Si no, revisalo en VirusTotal o pedí una segunda opinión.";
            }
            f.AttackIds.AddRange(d.AttackIds.Except(f.AttackIds));
        }
    }

    // ---------------------------------------------------------------- H-28
    private static void H28_Driver(RuleContext ctx, HeuristicDefinition def)
    {
        foreach (var d in ctx.Snapshot.Drivers)
        {
            var b = ctx.Snapshot.GetBinary(d.BinaryKey);
            if (b is null) continue;
            var lol = b.Sha256 is not null && ctx.Feeds.LolDrivers.TryGetValue(b.Sha256, out var hit) ? hit
                    : b.Sha1 is not null && ctx.Feeds.LolDrivers.TryGetValue(b.Sha1, out hit) ? hit
                    : b.Md5 is not null && ctx.Feeds.LolDrivers.TryGetValue(b.Md5, out hit) ? hit : null;
            bool unsigned = ctx.IsUnsigned(b);
            if (lol is null && !unsigned) continue;
            var motivo = lol is not null ? $" (figura en LOLDrivers como {lol.Category})" : " (no tiene firma digital)";
            ctx.Emit(def, d, b.Key, new() { ["nombre"] = d.DisplayName, ["motivo"] = motivo },
                Raw(("driver", d.Name), ("path", b.Path), ("sha256", b.Sha256), ("state", d.State), ("loldrivers", lol?.Category), ("unsigned", unsigned)));
        }
    }

    // ---------------------------------------------------------------- H-29
    private static void H29_LogCleared(RuleContext ctx, HeuristicDefinition def)
    {
        foreach (var e in ctx.Snapshot.Events.Where(e => e.EventId is 1102 or 104))
        {
            var log = e.EventId == 1102 ? "Seguridad" : e.Data.GetValueOrDefault("Channel") ?? e.Data.GetValueOrDefault("p1") ?? "Sistema";
            ctx.Emit(def, e, "logclear", new() { ["log"] = log, ["fecha"] = e.Timestamp.ToString("dd/MM/yyyy HH:mm") },
                Raw(("eventId", e.EventId), ("log", e.Log), ("time", e.Timestamp.ToString("O")), ("user", e.Data.GetValueOrDefault("SubjectUserName"))));
        }
    }

    // ---------------------------------------------------------------- H-30
    private static void H30_NewService(RuleContext ctx, HeuristicDefinition def)
    {
        foreach (var e in ctx.Snapshot.Events.Where(e => e.EventId == 7045))
        {
            var image = e.Data.GetValueOrDefault("ImagePath") ?? "";
            var name = e.Data.GetValueOrDefault("ServiceName") ?? "?";
            var path = CommandLineResolver.Resolve(image).Executable;
            var b = ctx.Snapshot.Binaries.Values.FirstOrDefault(x => path is not null && x.Path.Equals(path, StringComparison.OrdinalIgnoreCase));
            bool userFolder = PathClassifier.UserWritableFolder(path) is not null;
            bool unsigned = b is not null && ctx.IsUnsigned(b) && !ctx.IsHardAllowlisted(b);
            // ImagePath con comandos (powershell -enc, cmd /c) es típico de herramientas de ataque (PsExec, Cobalt Strike).
            bool scripted = Regex.IsMatch(image, @"(powershell|cmd(\.exe)?\s*/c|mshta|rundll32|%comspec%)", RegexOptions.IgnoreCase);
            if (!userFolder && !unsigned && !scripted) continue;
            ctx.Emit(def, e, b?.Key ?? $"service:{name}".ToLowerInvariant(), new() { ["nombre"] = name, ["fecha"] = e.Timestamp.ToString("dd/MM/yyyy HH:mm") },
                Raw(("service", name), ("imagePath", image), ("account", e.Data.GetValueOrDefault("AccountName")), ("userFolder", userFolder), ("unsigned", unsigned), ("scripted", scripted)));
        }
    }
}
