namespace Demiurge.Core.Util;

/// <summary>Ubicaciones de datos de la app. Todo bajo %ProgramData%\Demiurge (escribe el servicio como SYSTEM).</summary>
public static class DemiurgePaths
{
    public static string Root { get; set; } =
        Environment.GetEnvironmentVariable("DEMIURGE_HOME") ??
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Demiurge");

    public static string Database => Path.Combine(Root, "demiurge.db");
    public static string Feeds => Ensure(Path.Combine(Root, "feeds"));
    public static string Rules => Ensure(Path.Combine(Root, "rules"));
    public static string Quarantine => Ensure(Path.Combine(Root, "quarantine"));
    public static string Tools => Ensure(Path.Combine(Root, "tools"));
    public static string Logs => Ensure(Path.Combine(Root, "logs"));
    public static string Backups => Ensure(Path.Combine(Root, "backups"));
    public static string Config => Path.Combine(Root, "config.json");

    public static string Ensure(string dir)
    {
        Directory.CreateDirectory(dir);
        return dir;
    }
}
