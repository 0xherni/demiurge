using System.DirectoryServices.AccountManagement;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>COL-19: cuentas locales y miembros de Administradores.</summary>
public sealed class AccountCollector : ICollector
{
    public string Id => "COL-19";
    public string Name => "Cuentas locales";
    public int Order => 20;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var list = new List<LocalAccount>();
        using var pc = new PrincipalContext(ContextType.Machine);

        var adminSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            // S-1-5-32-544 = BUILTIN\Administrators (independiente del idioma).
            using var admins = GroupPrincipal.FindByIdentity(pc, IdentityType.Sid, "S-1-5-32-544");
            if (admins is not null)
                foreach (var m in admins.GetMembers())
                    using (m) if (m.Sid is not null) adminSids.Add(m.Sid.Value);
        }
        catch
        {
            // ignorar
        }

        var profiles = UserProfiles.All().ToDictionary(p => p.Sid, p => p.Path, StringComparer.OrdinalIgnoreCase);

        using var searcher = new PrincipalSearcher(new UserPrincipal(pc));
        foreach (var result in searcher.FindAll())
        {
            ct.ThrowIfCancellationRequested();
            if (result is not UserPrincipal u) { result.Dispose(); continue; }
            using (u)
            {
                var sid = u.Sid?.Value;
                var acc = new LocalAccount
                {
                    Name = u.SamAccountName ?? u.Name ?? "",
                    Sid = sid,
                    Enabled = u.Enabled ?? false,
                    IsAdmin = sid is not null && adminSids.Contains(sid),
                    LastLogon = u.LastLogon,
                    // RID 500 (Administrador), 501 (Invitado), 503 (DefaultAccount), 504 (WDAGUtilityAccount).
                    BuiltIn = sid is not null && (sid.EndsWith("-500") || sid.EndsWith("-501") || sid.EndsWith("-503") || sid.EndsWith("-504")),
                };
                // La fecha de creación no la expone la API: usamos la carpeta de perfil como aproximación
                // y, si está disponible, el evento 4720 (COL-23) la corrige.
                if (sid is not null && profiles.TryGetValue(sid, out var path))
                    try { acc.Created = Directory.GetCreationTime(path); } catch { }
                try
                {
                    foreach (var g in u.GetGroups()) using (g) acc.Groups.Add(g.Name);
                }
                catch
                {
                    // ignorar
                }
                list.Add(acc);
            }
        }

        ctx.Snapshot.AddRange(ctx.Snapshot.Accounts, list);
        return Task.FromResult(CollectorResult.Of(list.Count));
    }
}
