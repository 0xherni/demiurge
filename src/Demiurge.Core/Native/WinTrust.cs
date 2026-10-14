using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using Demiurge.Core.Model;

namespace Demiurge.Core.Native;

/// <summary>
/// Verificación Authenticode (COL-06): firma embebida y firma por catálogo
/// (muchos binarios de Windows no tienen firma embebida y sólo figuran en un .cat).
/// </summary>
internal static class WinTrust
{
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly Guid DRIVER_ACTION_VERIFY = new("F750E6C3-38EE-11d1-85E5-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    private const int CRYPT_E_FILE_ERROR = unchecked((int)0x80092003);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public string pcwszCatalogFilePath;
        public string pcwszMemberTag;
        public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile,
        ref uint pcbHash, [Out] byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash,
        uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    public static SignatureInfo Verify(string path)
    {
        var info = new SignatureInfo();
        try
        {
            int embedded = VerifyEmbedded(path);
            if (embedded == 0)
            {
                info.IsSigned = true;
                info.IsValid = true;
                FillSigner(info, path);
                return info;
            }

            if (embedded != TRUST_E_NOSIGNATURE && embedded != TRUST_E_SUBJECT_FORM_UNKNOWN &&
                embedded != TRUST_E_PROVIDER_UNKNOWN && embedded != CRYPT_E_FILE_ERROR)
            {
                // Tiene firma embebida pero no es válida (alterada, expirada sin timestamp, no confiable).
                info.IsSigned = true;
                info.IsValid = false;
                info.Error = $"0x{embedded:X8}";
                FillSigner(info, path);
                return info;
            }

            var catalog = VerifyCatalog(path, out var catalogFile);
            if (catalog is not null)
            {
                info.IsSigned = true;
                info.IsCatalogSigned = true;
                info.IsValid = catalog == 0;
                if (!info.IsValid) info.Error = $"0x{catalog:X8}";
                if (catalogFile is not null) FillSigner(info, catalogFile);
                return info;
            }

            info.IsSigned = false;
            info.IsValid = false;
            FillPackageSignature(info, path);
        }
        catch (Exception ex)
        {
            info.Error = ex.Message;
        }
        return info;
    }

    /// <summary>
    /// Apps MSIX (Microsoft Store / apps del sistema): los ejecutables no traen firma propia; la firma es del paquete
    /// (AppxSignature.p7x), Windows la valida al instalar y la carpeta WindowsApps/SystemApps sólo la escribe TrustedInstaller.
    /// </summary>
    private static void FillPackageSignature(SignatureInfo info, string path)
    {
        string? root = null;
        foreach (var marker in new[] { @"\WindowsApps\", @"\SystemApps\" })
        {
            int i = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (i < 0) continue;
            int start = i + marker.Length;
            int end = path.IndexOf('\\', start);
            if (end > start) root = path[..end];
        }
        if (root is null || !File.Exists(Path.Combine(root, "AppxSignature.p7x")) && !File.Exists(Path.Combine(root, "AppxManifest.xml"))) return;

        // El sufijo de la carpeta es el hash del publisher: 8wekyb3d8bbwe = Microsoft Corporation, cw5n1h2txyewy = Microsoft Windows.
        var folder = Path.GetFileName(root);
        info.IsSigned = true;
        info.IsValid = true;
        info.IsCatalogSigned = true;
        info.Signer = folder.EndsWith("_8wekyb3d8bbwe", StringComparison.OrdinalIgnoreCase) ? "Microsoft Corporation (paquete MSIX)"
            : folder.EndsWith("_cw5n1h2txyewy", StringComparison.OrdinalIgnoreCase) ? "Microsoft Windows (paquete MSIX)"
            : $"Paquete MSIX ({folder.Split('_')[0]})";
        info.Error = null;
    }

    private static int VerifyEmbedded(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
        };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = NewData(WTD_CHOICE_FILE, pFile);
            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return result;
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    /// <summary>Devuelve null si el archivo no figura en ningún catálogo; si figura, el resultado de WinVerifyTrust.</summary>
    private static int? VerifyCatalog(string path, out string? catalogFile)
    {
        catalogFile = null;
        if (!CryptCATAdminAcquireContext2(out var hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
            return null;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            uint cb = 0;
            CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fs.SafeFileHandle, ref cb, null, 0);
            if (cb == 0) return null;
            var hash = new byte[cb];
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fs.SafeFileHandle, ref cb, hash, 0))
                return null;

            IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, cb, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero) return null;
            try
            {
                var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                if (!CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0)) return null;
                catalogFile = ci.wszCatalogFile;

                var memberTag = Convert.ToHexString(hash);
                var cat = new WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                    pcwszCatalogFilePath = ci.wszCatalogFile,
                    pcwszMemberTag = memberTag,
                    pcwszMemberFilePath = path,
                    hCatAdmin = hCatAdmin,
                };
                IntPtr pCat = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                try
                {
                    Marshal.StructureToPtr(cat, pCat, false);
                    var data = NewData(WTD_CHOICE_CATALOG, pCat);
                    var action = DRIVER_ACTION_VERIFY;
                    int r = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                    data.dwStateAction = WTD_STATEACTION_CLOSE;
                    WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                    if (r != 0)
                    {
                        action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                        data = NewData(WTD_CHOICE_CATALOG, pCat);
                        r = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                        data.dwStateAction = WTD_STATEACTION_CLOSE;
                        WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                    }
                    return r;
                }
                finally
                {
                    Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(pCat);
                    Marshal.FreeHGlobal(pCat);
                }
            }
            finally
            {
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }
        }
        catch
        {
            return null;
        }
        finally
        {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    private static WINTRUST_DATA NewData(uint choice, IntPtr union) => new()
    {
        cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
        dwUIChoice = WTD_UI_NONE,
        fdwRevocationChecks = WTD_REVOKE_NONE,
        dwUnionChoice = choice,
        pUnion = union,
        dwStateAction = WTD_STATEACTION_VERIFY,
        // Sin chequeo de revocación online: el escaneo tiene que funcionar offline y rápido.
        dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
    };

    private static void FillSigner(SignatureInfo info, string signedFile)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
#pragma warning restore SYSLIB0057
            info.Signer = cert.GetNameInfo(X509NameType.SimpleName, false);
            info.Issuer = cert.GetNameInfo(X509NameType.SimpleName, true);
        }
        catch
        {
            // Sin datos del firmante: no es fatal.
        }
    }
}
