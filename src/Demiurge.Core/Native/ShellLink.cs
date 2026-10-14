using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace Demiurge.Core.Native;

/// <summary>Resolución de accesos directos .lnk vía IShellLinkW (COL-09).</summary>
internal static class ShellLink
{
    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    private class CShellLink { }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
    private interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cch, IntPtr pfd, uint fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cch);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cch);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cch);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        void GetHotkey(out short pwHotkey);
        void SetHotkey(short wHotkey);
        void GetShowCmd(out int piShowCmd);
        void SetShowCmd(int iShowCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath, int cch, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, uint dwReserved);
        void Resolve(IntPtr hwnd, uint fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }

    private const uint SLGP_RAWPATH = 0x4;

    public static (string? target, string? args) Resolve(string lnkPath)
    {
        object? obj = null;
        try
        {
            obj = new CShellLink();
            ((IPersistFile)obj).Load(lnkPath, 0);
            var link = (IShellLinkW)obj;
            var path = new StringBuilder(1024);
            link.GetPath(path, path.Capacity, IntPtr.Zero, SLGP_RAWPATH);
            var args = new StringBuilder(4096);
            link.GetArguments(args, args.Capacity);
            var target = Environment.ExpandEnvironmentVariables(path.ToString());
            return (string.IsNullOrEmpty(target) ? null : target, args.Length == 0 ? null : args.ToString());
        }
        catch
        {
            return (null, null);
        }
        finally
        {
            if (obj is not null) Marshal.ReleaseComObject(obj);
        }
    }
}
