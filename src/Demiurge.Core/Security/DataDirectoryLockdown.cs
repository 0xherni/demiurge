using System.Security.AccessControl;
using System.Security.Principal;
using Demiurge.Core.Native;
using Microsoft.Extensions.Logging;

namespace Demiurge.Core.Security;

/// <summary>
/// Protege %ProgramData%\Demiurge. Por defecto C:\ProgramData deja que cualquier usuario cree archivos en sus
/// subcarpetas: un programa sin privilegios podría plantar un ejecutable en tools\ (que el servicio correría como
/// SYSTEM), reglas o una base de conocimiento que lo marquen como benigno, o feeds envenenados.
///
/// Al arrancar el servicio (como SYSTEM):
///  1. Se corta la herencia y sólo SYSTEM y Administradores tienen acceso (los usuarios no leen ni escriben;
///     la app obtiene los datos por el pipe).
///  2. Todo archivo o carpeta cuyo dueño no sea SYSTEM/Administradores/TrustedInstaller se considera plantado:
///     se mueve a untrusted\ y nunca se carga.
/// </summary>
public static class DataDirectoryLockdown
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    public static bool IsTrustedOwner(SecurityIdentifier? owner) =>
        owner is not null && (owner.Equals(System) || owner.Equals(Admins) || owner.Equals(TrustedInstaller));

    /// <summary>Dueño de un archivo o carpeta (null si no se puede leer).</summary>
    public static SecurityIdentifier? OwnerOf(string path)
    {
        try
        {
            FileSystemSecurity sec = Directory.Exists(path)
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner)
                : new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
            return sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Un archivo de configuración/reglas sólo se usa si lo creó SYSTEM o un administrador.
    /// (En modo --local sin privilegios no hay forma de garantizarlo: se acepta y se avisa.)
    /// </summary>
    public static bool CanTrust(string path) => !ProcessNative.IsAdministrator() || IsTrustedOwner(OwnerOf(path));

    public static void Apply(string root, ILogger logger)
    {
        if (!ProcessNative.IsAdministrator())
        {
            logger.LogWarning("Sin privilegios: no se puede proteger {Root}. Abrí Demiurge como administrador para que los datos queden protegidos.", root);
            return;
        }

        Directory.CreateDirectory(root);
        var dir = new DirectoryInfo(root);

        // Si la carpeta raíz la creó otro usuario antes de instalar ("squatting"), tomamos posesión primero.
        var rootSec = dir.GetAccessControl();
        if (!IsTrustedOwner(rootSec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier))
        {
            logger.LogWarning("{Root} tenía un dueño no confiable: se toma posesión", root);
            rootSec.SetOwner(Admins);
            dir.SetAccessControl(rootSec);
        }

        var sec = new DirectorySecurity();
        sec.SetOwner(Admins);
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { System, Admins })
            sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(sec);

        // Revisar lo que ya existía: lo que no creó SYSTEM/Administradores se aparta.
        var untrusted = Path.Combine(root, "untrusted");
        int moved = 0;
        foreach (var entry in WalkWithoutFollowingLinks(dir).ToList())
        {
            if (entry.FullName.StartsWith(untrusted, StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                // Un enlace adentro de nuestra carpeta nunca es legítimo.
                bool isLink = entry.Attributes.HasFlag(FileAttributes.ReparsePoint);
                if (!isLink && IsTrustedOwner(OwnerOf(entry.FullName)))
                {
                    ResetToInherited(entry);
                    continue;
                }
                entry.Refresh();
                if (!entry.Exists) continue; // ya se apartó junto con su carpeta
                Directory.CreateDirectory(untrusted);
                var dest = Path.Combine(untrusted, $"{DateTime.Now:yyyyMMddHHmmss}_{Guid.NewGuid():N}_{entry.Name}");
                if (isLink)
                {
                    // Borrar el enlace (no su destino).
                    if (entry is DirectoryInfo d) d.Delete(); else entry.Delete();
                }
                else if (entry is DirectoryInfo d2) d2.MoveTo(dest);
                else ((FileInfo)entry).MoveTo(dest);
                moved++;
                logger.LogWarning("Se apartó {Path}: lo creó un usuario sin privilegios", entry.FullName);
            }
            catch (Exception ex)
            {
                logger.LogWarning("No se pudo revisar {Path}: {Error}", entry.FullName, ex.Message);
            }
        }
        logger.LogInformation("Carpeta de datos protegida ({Root}); {Moved} elemento(s) no confiables apartados", root, moved);
    }

    /// <summary>
    /// Recorre la carpeta sin entrar NUNCA en junctions/symlinks: si alguien plantó un enlace a C:\Windows,
    /// se devuelve el enlace (para borrarlo) pero no su contenido.
    /// </summary>
    private static IEnumerable<FileSystemInfo> WalkWithoutFollowingLinks(DirectoryInfo root)
    {
        var pending = new Stack<DirectoryInfo>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            FileSystemInfo[] children;
            try { children = current.GetFileSystemInfos("*", new EnumerationOptions { RecurseSubdirectories = false, AttributesToSkip = 0, IgnoreInaccessible = true }); }
            catch { continue; }
            foreach (var child in children)
            {
                yield return child;
                if (child is DirectoryInfo d && !d.Attributes.HasFlag(FileAttributes.ReparsePoint)) pending.Push(d);
            }
        }
    }

    /// <summary>Quita permisos explícitos (p.ej. los de CREATOR OWNER heredados de ProgramData) y deja sólo los heredados.</summary>
    private static void ResetToInherited(FileSystemInfo entry)
    {
        if (entry is DirectoryInfo d)
        {
            var s = new DirectorySecurity();
            s.SetOwner(Admins);
            s.SetAccessRuleProtection(false, false);
            d.SetAccessControl(s);
        }
        else if (entry is FileInfo f)
        {
            var s = new FileSecurity();
            s.SetOwner(Admins);
            s.SetAccessRuleProtection(false, false);
            f.SetAccessControl(s);
        }
    }
}
