using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Demiurge.Core.Native;

/// <summary>Lo que el registro de .NET no expone: fecha de modificación de una clave y carga de hives sueltos (Amcache).</summary>
public static class RegistryNative
{
    private const int KEY_READ = 0x20019;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegQueryInfoKeyW(SafeRegistryHandle hKey, IntPtr cls, IntPtr clsLen, IntPtr reserved,
        IntPtr subKeys, IntPtr maxSubKeyLen, IntPtr maxClassLen, IntPtr values, IntPtr maxValueNameLen, IntPtr maxValueLen,
        IntPtr securityDescriptor, out long lastWriteTime);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegLoadAppKeyW(string file, out SafeRegistryHandle key, int samDesired, int options, int reserved);

    /// <summary>Última modificación de la clave (o null si no se puede leer).</summary>
    public static DateTimeOffset? LastWrite(RegistryKey key)
    {
        try
        {
            if (RegQueryInfoKeyW(key.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var ft) != 0 || ft <= 0)
                return null;
            return DateTimeOffset.FromFileTime(ft);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Abre un hive como "app hive" (sólo lectura, no se monta en HKLM/HKU, se descarga al cerrar la clave).
    /// Si Windows ya lo tiene cargado, se comparte el mismo hive en memoria.
    /// </summary>
    public static RegistryKey LoadAppHive(string file)
    {
        int rc = RegLoadAppKeyW(file, out var handle, KEY_READ, 0, 0);
        if (rc != 0)
        {
            handle.Dispose();
            throw new System.ComponentModel.Win32Exception(rc);
        }
        return RegistryKey.FromHandle(handle);
    }
}
