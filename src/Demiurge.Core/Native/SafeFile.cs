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
        // No existe: se abre la carpeta padre, se verifica que sea la real (sin enlaces) y el archivo se crea RELATIVO a ese
        // handle. Verificar la ruta y después crear por ruta deja un instante en el que la carpeta se puede cambiar por un
        // enlace; con el handle, cambiar la ruta ya no afecta adónde se escribe.
        var full = Path.GetFullPath(originalPath);
        using var parent = OpenVerifiedDirectory(Path.GetDirectoryName(full)!, GENERIC_READ | FILE_ADD_FILE);
        using var created = CreateRelative(parent, Path.GetFileName(full));
        using var output = new FileStream(created, FileAccess.Write);
        output.Write(data);
    }

    /// <summary>
    /// Devuelve una carpeta respaldada (en la carpeta protegida de Demiurge) a su lugar original, con un rename relativo a
    /// la carpeta padre ya verificada (mismo motivo que <see cref="RestoreTo"/>).
    /// </summary>
    public static void RestoreDirectory(string backupDir, string originalPath)
    {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("Sólo Windows de 64 bits.");
        var full = Path.GetFullPath(originalPath);
        var name = Path.GetFileName(full);
        ValidateLeafName(name);
        using var parent = OpenVerifiedDirectory(Path.GetDirectoryName(full)!, GENERIC_READ | FILE_ADD_SUBDIRECTORY);
        using var src = CreateFileW(backupDir, DELETE | SYNCHRONIZE, FILE_SHARE_READ | 2 | 4, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (src.IsInvalid) throw new IOException($"No se pudo abrir {backupDir}: {Marshal.GetLastPInvokeErrorMessage()}");
        if (!GetFileInformationByHandle(src, out var info) || (info.Attributes & 0x10) == 0 || (info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw new SecurityException("El respaldo no es una carpeta común; se cancela la restauración.");

        // FILE_RENAME_INFORMATION (x64): Flags/ReplaceIfExists @0, RootDirectory @8, FileNameLength @16, FileName @20.
        int size = 20 + (name.Length + 1) * 2;
        var buf = Marshal.AllocHGlobal(size);
        bool added = false;
        try
        {
            for (int i = 0; i < size; i++) Marshal.WriteByte(buf, i, 0);
            parent.DangerousAddRef(ref added);
            Marshal.WriteIntPtr(buf, 8, parent.DangerousGetHandle());
            Marshal.WriteInt32(buf, 16, name.Length * 2);
            Marshal.Copy(name.ToCharArray(), 0, buf + 20, name.Length);
            int status = NtSetInformationFile(src, out _, buf, (uint)size, FileRenameInformation);
            if (status < 0) throw new IOException("No se pudo restaurar la carpeta: " + new System.ComponentModel.Win32Exception((int)RtlNtStatusToDosError(status)).Message);
        }
        finally
        {
            if (added) parent.DangerousRelease();
            Marshal.FreeHGlobal(buf);
        }
    }

    private const uint SYNCHRONIZE = 0x00100000;
    private const uint FILE_ADD_FILE = 0x0002;
    private const uint FILE_ADD_SUBDIRECTORY = 0x0004;
    private const int FileRenameInformation = 10;

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref OBJECT_ATTRIBUTES oa, out IO_STATUS_BLOCK iosb,
        IntPtr allocationSize, uint fileAttributes, uint share, uint disposition, uint options, IntPtr eaBuffer, uint eaLength);

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationFile(SafeFileHandle handle, out IO_STATUS_BLOCK iosb, IntPtr info, uint length, int infoClass);

    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);

    /// <summary>Abre una carpeta y verifica (por el handle) que no sea un enlace y que su ruta real sea la esperada.</summary>
    private static SafeFileHandle OpenVerifiedDirectory(string dir, uint access)
    {
        var h = CreateFileW(dir, access, FILE_SHARE_READ | 2 | 4, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h.IsInvalid) throw new IOException($"No se pudo abrir {dir}: {Marshal.GetLastPInvokeErrorMessage()}");
        try
        {
            if (!GetFileInformationByHandle(h, out var info) || (info.Attributes & 0x10) == 0)
                throw new IOException($"{dir} no es una carpeta.");
            if ((info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new SecurityException($"{dir} es un enlace a otra carpeta; por seguridad se cancela la acción.");
            CheckFinalPath(h, dir);
            return h;
        }
        catch
        {
            h.Dispose();
            throw;
        }
    }

    /// <summary>Crea un archivo NUEVO dentro de la carpeta del handle (falla si ya existe algo con ese nombre, incluso un enlace).</summary>
    private static SafeFileHandle CreateRelative(SafeFileHandle parent, string name)
    {
        ValidateLeafName(name);
        var namePtr = Marshal.StringToHGlobalUni(name);
        var usPtr = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>());
        bool added = false;
        try
        {
            Marshal.StructureToPtr(new UNICODE_STRING { Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2 + 2), Buffer = namePtr }, usPtr, false);
            parent.DangerousAddRef(ref added);
            var oa = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = usPtr,
                Attributes = 0x40, // OBJ_CASE_INSENSITIVE
            };
            int status = NtCreateFile(out var h, GENERIC_WRITE | SYNCHRONIZE, ref oa, out _, IntPtr.Zero, 0x80 /*NORMAL*/, 0,
                2 /*FILE_CREATE*/, 0x40 | 0x20 /*NON_DIRECTORY_FILE | SYNCHRONOUS_IO_NONALERT*/, IntPtr.Zero, 0);
            if (status < 0)
            {
                h.Dispose();
                throw new IOException("No se pudo crear el archivo: " + new System.ComponentModel.Win32Exception((int)RtlNtStatusToDosError(status)).Message);
            }
            return h;
        }
        finally
        {
            if (added) parent.DangerousRelease();
            Marshal.FreeHGlobal(usPtr);
            Marshal.FreeHGlobal(namePtr);
        }
    }

    private static void ValidateLeafName(string name)
    {
        if (string.IsNullOrEmpty(name) || name is "." or ".." || name.IndexOfAny(['\\', '/', ':']) >= 0)
            throw new SecurityException($"Nombre de archivo inválido: {name}");
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
