namespace Demiurge.Core.Util;

/// <summary>Clasifica rutas: carpetas de usuario (H-04), ubicaciones oficiales del sistema (H-05).</summary>
public static class PathClassifier
{
    private static readonly string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
    private static readonly string System32 = Path.Combine(Windows, "System32") + "\\";
    private static readonly string SysWow64 = Path.Combine(Windows, "SysWOW64") + "\\";
    private static readonly string ProgramFiles = (Environment.GetEnvironmentVariable("ProgramW6432") ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)).TrimEnd('\\') + "\\";
    private static readonly string ProgramFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).TrimEnd('\\') + "\\";
    private static readonly string ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).TrimEnd('\\') + "\\";

    /// <summary>Devuelve un nombre legible de la carpeta "de usuario" o null si no lo es.</summary>
    public static string? UserWritableFolder(string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        var p = path.Replace('/', '\\');
        if (Contains(p, @"\AppData\Local\Temp\") || Contains(p, @"\Windows\Temp\")) return "Temp";
        if (Contains(p, @"\AppData\Roaming\")) return "AppData\\Roaming";
        if (Contains(p, @"\AppData\Local\Microsoft\WindowsApps\")) return null; // alias de apps de la Store
        if (Contains(p, @"\AppData\Local\")) return "AppData\\Local";
        if (Contains(p, @"\AppData\LocalLow\")) return "AppData\\LocalLow";
        if (Contains(p, @"\Users\Public\")) return "Users\\Public";
        if (Contains(p, @"\Downloads\")) return "Descargas";
        if (Contains(p, @"\Desktop\")) return "Escritorio";
        if (p.StartsWith(ProgramData, StringComparison.OrdinalIgnoreCase))
        {
            // Defender y paquetes de Microsoft viven en ProgramData legítimamente.
            if (Contains(p, @"\ProgramData\Microsoft\Windows Defender\") || Contains(p, @"\ProgramData\Microsoft\Windows\Start Menu\") ) return null;
            if (Contains(p, @"\ProgramData\Package Cache\")) return null;
            return "ProgramData";
        }
        return null;
    }

    public static bool IsInWindowsDir(string? path) =>
        path is not null && path.StartsWith(Windows, StringComparison.OrdinalIgnoreCase);

    public static bool IsSystem32(string? path) =>
        path is not null && (path.StartsWith(System32, StringComparison.OrdinalIgnoreCase) || path.StartsWith(SysWow64, StringComparison.OrdinalIgnoreCase));

    public static bool IsProgramFiles(string? path) =>
        path is not null && (path.StartsWith(ProgramFiles, StringComparison.OrdinalIgnoreCase) || path.StartsWith(ProgramFilesX86, StringComparison.OrdinalIgnoreCase));

    public static string WindowsDir => Windows;
    public static string System32Dir => System32;

    private static bool Contains(string path, string fragment) =>
        path.Contains(fragment, StringComparison.OrdinalIgnoreCase);

    /// <summary>Doble extensión: factura.pdf.exe, foto.jpg .scr, etc.</summary>
    public static bool HasDoubleExtension(string fileName)
    {
        var lower = fileName.ToLowerInvariant();
        string[] exec = [".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".hta", ".lnk", ".pif", ".msi", ".ps1", ".wsf"];
        string[] docs = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".mp3", ".mp4", ".avi", ".zip", ".rar", ".rtf", ".csv"];
        var ext = Path.GetExtension(lower);
        if (!exec.Contains(ext)) return false;
        var inner = Path.GetExtension(Path.GetFileNameWithoutExtension(lower).TrimEnd(' ', '.'));
        if (docs.Contains(inner)) return true;
        // Muchos espacios antes de la extensión real ("documento.pdf          .exe").
        return lower.Contains("     ");
    }
}
