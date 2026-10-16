namespace Demiurge.Core.Util;

/// <summary>Ubicaciones de datos de la app. Todo bajo %ProgramData%\Demiurge.</summary>
public static class DemiurgePaths
{
    /// <summary>
    /// %ProgramData%\Demiurge. DEMIURGE_HOME sólo se respeta SIN privilegios (desarrollo y pruebas): cualquier programa
    /// del usuario puede definir esa variable, y si la app elevada la usara, apuntándola a C:\Windows la protección de la
    /// carpeta de datos le cambiaría los permisos a todo Windows.
    /// </summary>
    public static string Root { get; set; } = ResolveRoot(Environment.GetEnvironmentVariable("DEMIURGE_HOME"), Native.ProcessNative.IsAdministrator());

    internal static string ResolveRoot(string? overrideDir, bool elevated) =>
        !elevated && !string.IsNullOrWhiteSpace(overrideDir)
            ? overrideDir
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Demiurge");

    /// <summary>
    /// Se vuelve true cuando la carpeta de datos ya está protegida (o cuando no hay privilegios para protegerla).
    /// Antes de eso no se escribe nada adentro: ni siquiera el log.
    /// </summary>
    public static volatile bool Secured;

    public static string Database => Path.Combine(Root, "demiurge.db");
    public static string Feeds => Ensure(Path.Combine(Root, "feeds"));
    public static string Rules => Ensure(Path.Combine(Root, "rules"));
    public static string Quarantine => Ensure(Path.Combine(Root, "quarantine"));
    public static string Tools => Ensure(Path.Combine(Root, "tools"));
    public static string Logs => Ensure(Path.Combine(Root, "logs"));
    public static string Backups => Ensure(Path.Combine(Root, "backups"));
    public static string Temp => Ensure(Path.Combine(Root, "tmp"));
    public static string Config => Path.Combine(Root, "config.json");

    public static string Ensure(string dir)
    {
        Directory.CreateDirectory(dir);
        return dir;
    }
}
