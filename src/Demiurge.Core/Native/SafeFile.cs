using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Demiurge.Core.Native;

/// <summary>
/// Operaciones de archivo seguras para cuando el servicio (SYSTEM) toca rutas que controla un usuario
/// (perfiles de navegador, carpeta Inicio, binarios a poner en cuarentena).
///
/// Ataques que evita:
///  - Junctions / symlinks: un usuario cambia una carpeta por un enlace a C:\Windows justo antes de la acción,
///    y SYSTEM termina escribiendo o borrando ahí. Se abre un handle y se compara la ruta REAL del handle con
///    la esperada; si difieren, se aborta.
///  - Hardlinks: un hardlink en el perfil apuntando a un archivo del sistema pasa el chequeo de ruta, así que se
///    rechazan archivos con más de un enlace.
///  - Carreras entre chequeo y uso: todo (lectura, escritura, borrado) se hace sobre el mismo handle verificado.
/// </summary>
public static class SafeFile
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint DELETE = 0x00010000;
    private const uint FILE_SHARE_READ = 1;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder path, uint len, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetLongPathNameW(string shortPath, StringBuilder longPath, uint len);

    // Pack = 4: los FILETIME de Windows son dos DWORD (alineación 4); con long se correría el resto de los campos.
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint Attributes;
        public long Created, Accessed, Written;
        public uint VolumeSerial, SizeHigh, SizeLow, NumberOfLinks, IndexHigh, IndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle h, int infoClass, ref byte deleteFile, uint size);

    private const int FileDispositionInfo = 4;

    /// <summary>Lee un archivo verificando que la ruta no fue redirigida.</summary>
    public static byte[] ReadAllBytes(string path, long maxBytes = 256L * 1024 * 1024)
    {
        using var h = Open(path, GENERIC_READ, FILE_SHARE_READ | 2 /*WRITE*/ | 4 /*DELETE*/, 0);
        using var fs = new FileStream(h, FileAccess.Read);
        if (fs.Length > maxBytes) throw new IOException($"Archivo demasiado grande para procesar: {path}");
        var buf = new byte[fs.Length];
        fs.ReadExactly(buf);
        return buf;
    }

    public static string ReadAllText(string path) => Encoding.UTF8.GetString(ReadAllBytes(path, 64L * 1024 * 1024)).TrimStart('\uFEFF');

    /// <summary>Sobrescribe un archivo existente verificando la ruta (no crea archivos nuevos en rutas de usuario).</summary>
    public static void WriteAllText(string path, string content)
    {
        using var h = Open(path, GENERIC_READ | GENERIC_WRITE, 0, 0);
        using var fs = new FileStream(h, FileAccess.ReadWrite);
        var bytes = new UTF8Encoding(false).GetBytes(content);
        fs.SetLength(0);
        fs.Write(bytes);
    }

    public static void WriteAllBytes(string path, byte[] data)
    {
        using var h = Open(path, GENERIC_READ | GENERIC_WRITE, 0, 0);
        using var fs = new FileStream(h, FileAccess.ReadWrite);
        fs.SetLength(0);
        fs.Write(data);
    }

    /// <summary>
    /// Copia el contenido a <paramref name="destination"/> (que debe estar en una carpeta de Demiurge, protegida) y
    /// borra el original a través del mismo handle verificado. Si el original es un enlace, se borra el enlace.
    /// </summary>
    public static void MoveOut(string path, string destination, Func<byte[], byte[]>? transform = null, string? expectedSha256 = null)
    {
        using var h = Open(path, GENERIC_READ | DELETE, FILE_SHARE_READ, FILE_FLAG_OPEN_REPARSE_POINT);
        byte[] data;
        using (var fs = new FileStream(h, FileAccess.Read, 1, false) { })
        {
            data = new byte[fs.Length];
            fs.ReadExactly(data);
            if (expectedSha256 is not null)
            {
                var actual = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(data));
                if (!actual.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
                    throw new SecurityException("El archivo cambió desde el escaneo; volvé a escanear antes de actuar.");
            }
            File.WriteAllBytes(destination, transform is null ? data : transform(data));
            byte del = 1;
            if (!SetFileInformationByHandle(h, FileDispositionInfo, ref del, 1))
            {
                File.Delete(destination);
                throw new IOException("No se pudo borrar el original: " + Marshal.GetLastPInvokeErrorMessage());
            }
        }
    }

    /// <summary>Copia un archivo de usuario a una carpeta protegida (para backups) verificando la ruta de origen.</summary>
    public static void CopyOut(string path, string destination) => File.WriteAllBytes(destination, ReadAllBytes(path));

    /// <summary>Restaura un backup sobre una ruta de usuario: sólo sobrescribe si el destino existe y no está redirigido.</summary>
    public static void RestoreTo(string backup, string originalPath)
    {
        var data = File.ReadAllBytes(backup);
        if (File.Exists(originalPath))
        {
            using var h = Open(originalPath, GENERIC_READ | GENERIC_WRITE, 0, 0);
            using var fs = new FileStream(h, FileAccess.ReadWrite);
            fs.SetLength(0);
            fs.Write(data);
            return;
        }
        // No existe: verificar que la carpeta padre no esté redirigida y crear con CreateNew (falla si alguien lo creó en el medio).
        VerifyDirectory(Path.GetDirectoryName(originalPath)!);
        using var created = new FileStream(originalPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        created.Write(data);
    }

    /// <summary>Verifica que una carpeta no sea (ni cuelgue de) un junction/symlink que redirija a otro lado.</summary>
    public static void VerifyDirectory(string dir)
    {
        using var h = CreateFileW(dir, GENERIC_READ, FILE_SHARE_READ | 2 | 4, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (h.IsInvalid) throw new IOException($"No se pudo abrir {dir}: {Marshal.GetLastPInvokeErrorMessage()}");
        CheckFinalPath(h, dir);
    }

    private static SafeFileHandle Open(string path, uint access, uint share, uint extraFlags)
    {
        var h = CreateFileW(path, access, share, IntPtr.Zero, OPEN_EXISTING, extraFlags, IntPtr.Zero);
        if (h.IsInvalid) throw new IOException($"No se pudo abrir {path}: {Marshal.GetLastPInvokeErrorMessage()}");
        try
        {
            if (!GetFileInformationByHandle(h, out var info)) throw new IOException("No se pudo leer la información del archivo.");
            if ((info.Attributes & 0x10) != 0) throw new IOException($"{path} es una carpeta.");
            if (info.NumberOfLinks > 1) throw new SecurityException($"{path} tiene varios enlaces (hardlink); por seguridad no se toca.");
            // Con OPEN_REPARSE_POINT el handle es el enlace mismo: alcanza con verificar que la carpeta que lo contiene es la real.
            if ((extraFlags & FILE_FLAG_OPEN_REPARSE_POINT) != 0 && (info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                VerifyDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            else
                CheckFinalPath(h, path);
            return h;
        }
        catch
        {
            h.Dispose();
            throw;
        }
    }

    private static void CheckFinalPath(SafeFileHandle h, string expected)
    {
        var sb = new StringBuilder(1024);
        if (GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0) == 0) throw new IOException("No se pudo resolver la ruta real.");
        var real = Normalize(sb.ToString());
        var want = Normalize(LongPath(Path.GetFullPath(expected)));
        if (!string.Equals(real, want, StringComparison.OrdinalIgnoreCase))
            throw new SecurityException($"La ruta fue redirigida ({expected} → {real}); por seguridad se cancela la acción.");
    }

    private static string LongPath(string p)
    {
        var sb = new StringBuilder(1024);
        return GetLongPathNameW(p, sb, (uint)sb.Capacity) > 0 ? sb.ToString() : p;
    }

    private static string Normalize(string p)
    {
        if (p.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) p = @"\\" + p[8..];
        else if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        return p.TrimEnd('\\');
    }
}
