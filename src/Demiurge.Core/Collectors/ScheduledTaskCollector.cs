using Microsoft.Win32;
using Microsoft.Win32.TaskScheduler;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>COL-10: tareas programadas (incluidas subcarpetas y tareas escondidas por borrado de SD).</summary>
public sealed class ScheduledTaskCollector : ICollector
{
    public string Id => "COL-10";
    public string Name => "Arranque: tareas programadas";
    public int Order => 20;

    public System.Threading.Tasks.Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var items = new List<PersistenceItem>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>();

        try
        {
            using var ts = new TaskService();
            foreach (var task in EnumerateAll(ts.RootFolder))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    seen.Add(task.Path);
                    var def = task.Definition;
                    var triggers = string.Join("; ", def.Triggers.Select(t => t.ToString()));
                    foreach (var action in def.Actions)
                    {
                        string command;
                        string? target;
                        string? args = null;
                        if (action is ExecAction exec)
                        {
                            var r = CommandLineResolver.Resolve($"\"{Environment.ExpandEnvironmentVariables(exec.Path ?? "")}\" {exec.Arguments}");
                            target = r.HostedModule ?? r.Executable;
                            args = exec.Arguments;
                            command = $"{exec.Path} {exec.Arguments}".Trim();
                        }
                        else if (action is ComHandlerAction com)
                        {
                            target = ResolveClsid(com.ClassId.ToString("B"));
                            command = $"COM {com.ClassId:B} {com.Data}".Trim();
                        }
                        else
                        {
                            continue;
                        }

                        items.Add(new PersistenceItem
                        {
                            Type = PersistenceType.Task,
                            Location = task.Path,
                            Name = task.Name,
                            Command = command,
                            ResolvedPath = target,
                            Arguments = args,
                            Author = def.RegistrationInfo.Author,
                            RunAs = def.Principal.UserId ?? def.Principal.GroupId,
                            Hidden = def.Settings.Hidden,
                            Enabled = task.Enabled,
                            BinaryKey = ctx.Binaries.Register(target),
                            Extra =
                            {
                                ["triggers"] = triggers,
                                ["runLevel"] = def.Principal.RunLevel.ToString(),
                                ["lastRun"] = task.LastRunTime == DateTime.MinValue ? "" : task.LastRunTime.ToString("O"),
                            },
                        });
                    }
                }
                catch (Exception ex)
                {
                    warnings.Add($"{task.Path}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add("Task Scheduler: " + ex.Message);
        }

        // Tareas escondidas quitando el valor SD en TaskCache\Tree (técnica "Tarrask"): no aparecen en la API.
        items.AddRange(FindSdlessTasks(ctx, seen));

        ctx.Snapshot.AddRange(ctx.Snapshot.Persistence, items);
        return System.Threading.Tasks.Task.FromResult(new CollectorResult { ItemCount = items.Count, Warnings = warnings });
    }

    private static IEnumerable<Microsoft.Win32.TaskScheduler.Task> EnumerateAll(TaskFolder folder)
    {
        TaskCollection? tasks = null;
        try { tasks = folder.Tasks; } catch { /* carpeta sin permisos */ }
        if (tasks is not null)
            foreach (var t in tasks) yield return t;

        TaskFolderCollection? subs = null;
        try { subs = folder.SubFolders; } catch { }
        if (subs is null) yield break;
        foreach (var sub in subs)
            foreach (var t in EnumerateAll(sub))
                yield return t;
    }

    private static IEnumerable<PersistenceItem> FindSdlessTasks(ScanContext ctx, HashSet<string> seen)
    {
        var list = new List<PersistenceItem>();
        try
        {
            using var tree = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree");
            if (tree is null) return list;
            Walk(tree, "");

            void Walk(RegistryKey key, string path)
            {
                foreach (var name in key.GetSubKeyNames())
                {
                    using var sub = key.OpenSubKey(name);
                    if (sub is null) continue;
                    var taskPath = path + "\\" + name;
                    var id = sub.GetValue("Id") as string;
                    if (id is null)
                    {
                        Walk(sub, taskPath);
                        continue;
                    }
                    if (sub.GetValue("SD") is null && !seen.Contains(taskPath))
                    {
                        using var t = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{id}");
                        var actionsBlob = t?.GetValue("Actions") as byte[];
                        var cmd = actionsBlob is null ? null : ExtractCommand(actionsBlob);
                        var r = CommandLineResolver.Resolve(cmd);
                        list.Add(new PersistenceItem
                        {
                            Type = PersistenceType.Task,
                            Location = taskPath,
                            Name = name,
                            Command = cmd ?? "(desconocido)",
                            ResolvedPath = r.Executable,
                            Hidden = true,
                            BinaryKey = ctx.Binaries.Register(r.Executable),
                            Extra = { ["sdRemoved"] = "true" },
                        });
                    }
                }
            }
        }
        catch
        {
            // ignorar
        }
        return list;
    }

    /// <summary>El blob Actions guarda strings UTF-16; tomamos el primero que parezca un ejecutable.</summary>
    private static string? ExtractCommand(byte[] blob)
    {
        var text = System.Text.Encoding.Unicode.GetString(blob);
        var parts = text.Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .Select(s => new string(s.Where(c => !char.IsControl(c)).ToArray()).Trim())
            .Where(s => s.Length > 3)
            .ToList();
        var exe = parts.FirstOrDefault(s => s.Contains('\\') || s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
        if (exe is null) return null;
        int i = parts.IndexOf(exe);
        var args = i + 1 < parts.Count ? parts[i + 1] : "";
        return $"\"{exe}\" {args}".Trim();
    }

    internal static string? ResolveClsid(string clsid)
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, view);
                using var k = root.OpenSubKey($@"CLSID\{clsid}\InprocServer32") ?? root.OpenSubKey($@"CLSID\{clsid}\LocalServer32");
                var v = k?.GetValue(null)?.ToString();
                if (!string.IsNullOrWhiteSpace(v)) return CommandLineResolver.Resolve(v).Executable;
            }
            catch
            {
                // ignorar
            }
        }
        return null;
    }
}
