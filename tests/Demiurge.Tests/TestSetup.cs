using System.Runtime.CompilerServices;
using Demiurge.Core.Util;

namespace Demiurge.Tests;

internal static class TestSetup
{
    /// <summary>
    /// Los tests nunca usan la carpeta de datos real (%ProgramData%\Demiurge): con Demiurge instalado sólo la pueden
    /// abrir los administradores, y además los tests no deben tocar los datos del usuario.
    /// </summary>
    [ModuleInitializer]
    internal static void UseTemporaryDataFolder()
    {
        var dir = Path.Combine(Path.GetTempPath(), "demiurge-tests-" + Environment.ProcessId);
        Directory.CreateDirectory(dir);
        DemiurgePaths.Root = dir;
    }
}
