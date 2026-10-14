using Microsoft.Win32;

namespace Demiurge.Core.Util;

/// <summary>
/// El servicio corre como SYSTEM: para ver lo de cada usuario hay que recorrer sus perfiles
/// (carpetas) y sus hives cargados en HKEY_USERS.
/// </summary>
public static class UserProfiles
{
    public sealed record Profile(string Sid, string UserName, string Path);

    public static List<Profile> All()
    {
        var list = new List<Profile>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (key is null) return list;
            foreach (var sid in key.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) continue;
                using var p = key.OpenSubKey(sid);
                var path = p?.GetValue("ProfileImagePath") as string;
                if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) continue;
                list.Add(new Profile(sid, System.IO.Path.GetFileName(path), path));
            }
        }
        catch
        {
            // sin acceso al ProfileList: al menos el usuario actual
        }
        if (list.Count == 0)
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            list.Add(new Profile(System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "", Environment.UserName, home));
        }
        return list;
    }

    /// <summary>
    /// Hives de usuario accesibles: HKU\{SID} de los usuarios con sesión. Si el proceso no es SYSTEM,
    /// devuelve HKCU como fallback.
    /// </summary>
    public static List<(string Sid, string User, RegistryKey Root)> UserHives()
    {
        var result = new List<(string, string, RegistryKey)>();
        var profiles = All().ToDictionary(p => p.Sid, p => p.UserName, StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var sid in Registry.Users.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.EndsWith("_Classes", StringComparison.Ordinal)) continue;
                var root = Registry.Users.OpenSubKey(sid);
                if (root is null) continue;
                result.Add((sid, profiles.GetValueOrDefault(sid, sid), root));
            }
        }
        catch
        {
            // ignorar
        }
        if (result.Count == 0)
            result.Add((System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "", Environment.UserName, Registry.CurrentUser));
        return result;
    }

    public static string LocalAppData(Profile p) => System.IO.Path.Combine(p.Path, "AppData", "Local");
    public static string RoamingAppData(Profile p) => System.IO.Path.Combine(p.Path, "AppData", "Roaming");
}
