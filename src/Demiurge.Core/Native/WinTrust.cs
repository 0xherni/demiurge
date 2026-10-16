using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;
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
                FillSigner(info, path, catalog: false);
                return info;
            }

            if (embedded != TRUST_E_NOSIGNATURE && embedded != TRUST_E_SUBJECT_FORM_UNKNOWN &&
                embedded != TRUST_E_PROVIDER_UNKNOWN && embedded != CRYPT_E_FILE_ERROR)
            {
                // Tiene firma embebida pero no es válida (alterada, expirada sin timestamp, no confiable).
                info.IsSigned = true;
                info.IsValid = false;
                info.Error = $"0x{embedded:X8}";
                FillSigner(info, path, catalog: false);
                return info;
            }

            var catalog = VerifyCatalog(path, out var catalogFile);
            if (catalog is not null)
            {
                info.IsSigned = true;
                info.IsCatalogSigned = true;
                info.IsValid = catalog == 0;
                if (!info.IsValid) info.Error = $"0x{catalog:X8}";
                if (catalogFile is not null) FillSigner(info, catalogFile, catalog: true);
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
    /// (AppxSignature.p7x) y Windows la valida al instalar. Sólo se acepta en las carpetas que únicamente escribe
    /// TrustedInstaller (%ProgramFiles%\WindowsApps y %windir%\SystemApps), y el firmante sale del certificado del
    /// paquete, no del nombre de la carpeta: una carpeta "WindowsApps" en Temp con un sufijo copiado no vale nada.
    /// </summary>
    private static void FillPackageSignature(SignatureInfo info, string path)
    {
        var root = PackageRoot(path);
        if (root is null) return;
        try
        {
            var p7x = Path.Combine(root, "AppxSignature.p7x");
            if (!File.Exists(p7x)) return;
            var bytes = File.ReadAllBytes(p7x);
            // Formato: "PKCX" + PKCS#7 (DER).
            if (bytes.Length < 8 || bytes[0] != (byte)'P' || bytes[1] != (byte)'K' || bytes[2] != (byte)'C' || bytes[3] != (byte)'X') return;
            var cms = DecodeCms(bytes.AsSpan(4).ToArray());
            if (cms is null) return;
            var (signer, issuer, rootThumb) = Inspect(cms);
            if (signer is null) return;
            info.IsSigned = true;
            info.IsValid = true;
            info.IsCatalogSigned = true;
            info.Signer = $"{signer} (paquete MSIX)";
            info.Issuer = issuer;
            info.RootThumbprint = rootThumb;
            info.ChainChecked = true;
            info.Error = null;
        }
        catch
        {
            // Sin firma de paquete legible: queda como sin firma.
        }
    }

    /// <summary>Carpeta del paquete si el archivo está DENTRO de una carpeta protegida de paquetes; si no, null.</summary>
    internal static string? PackageRoot(string path)
    {
        string full;
        try { full = Path.GetFullPath(path); } catch { return null; }
        foreach (var protectedBase in new[]
                 {
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps"),
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SystemApps"),
                 })
        {
            var prefix = protectedBase.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            int end = full.IndexOf(Path.DirectorySeparatorChar, prefix.Length);
            if (end > prefix.Length) return full[..end];
        }
        return null;
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

    /// <summary>Catálogos (.cat) ya inspeccionados: muchos binarios de Windows comparten el mismo.</summary>
    private static readonly ConcurrentDictionary<string, (string? Signer, string? Issuer, string? Root)> CatalogCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Firmante y raíz de la cadena, leídos del PKCS#7 del archivo (PE) o del catálogo.</summary>
    private static void FillSigner(SignatureInfo info, string signedFile, bool catalog)
    {
        info.ChainChecked = true;
        try
        {
            if (catalog && CatalogCache.TryGetValue(signedFile, out var cached))
            {
                (info.Signer, info.Issuer, info.RootThumbprint) = cached;
                return;
            }
            var cms = catalog ? DecodeCms(File.ReadAllBytes(signedFile)) : ReadPeSignature(signedFile);
            if (cms is null) return;
            var result = Inspect(cms);
            (info.Signer, info.Issuer, info.RootThumbprint) = result;
            if (catalog) CatalogCache[signedFile] = result;
        }
        catch
        {
            // Sin datos del firmante: no es fatal (IsMicrosoft queda en false porque no hay raíz verificada).
        }
    }

    internal static (string? Signer, string? Issuer, string? Root) Inspect(SignedCms cms)
    {
        if (cms.SignerInfos.Count == 0) return (null, null, null);
        var cert = cms.SignerInfos[0].Certificate;
        if (cert is null) return (null, null, null);
        return (cert.GetNameInfo(X509NameType.SimpleName, false), cert.GetNameInfo(X509NameType.SimpleName, true), ChainRoot(cert, cms.Certificates));
    }

    /// <summary>
    /// Huella del certificado raíz de la cadena, o null si la cadena no se pudo armar con firmas válidas. No alcanza con
    /// que la cadena "llegue" a una raíz por nombre: un firmante falso que dice ser emitido por Microsoft arma una cadena
    /// hasta la raíz real, pero con una firma inválida en el medio. Por eso cualquier error de firma descarta el resultado.
    /// (WinVerifyTrust ya decidió si la firma es de confianza; acá sólo se identifica QUIÉN es la raíz.)
    /// </summary>
    internal static string? ChainRoot(X509Certificate2 leaf, X509Certificate2Collection extra)
    {
        using var chain = new X509Chain();
        var p = chain.ChainPolicy;
        p.RevocationMode = X509RevocationMode.NoCheck;
        p.DisableCertificateDownloads = true;
        p.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority | X509VerificationFlags.IgnoreNotTimeValid |
                              X509VerificationFlags.IgnoreNotTimeNested | X509VerificationFlags.IgnoreWrongUsage |
                              X509VerificationFlags.IgnoreInvalidPolicy | X509VerificationFlags.IgnoreCtlNotTimeValid;
        p.ExtraStore.AddRange(extra);
        chain.Build(leaf);
        const X509ChainStatusFlags fatal = X509ChainStatusFlags.NotSignatureValid | X509ChainStatusFlags.Cyclic |
                                           X509ChainStatusFlags.PartialChain | X509ChainStatusFlags.InvalidBasicConstraints |
                                           X509ChainStatusFlags.HasNotSupportedCriticalExtension | X509ChainStatusFlags.ExplicitDistrust;
        foreach (var element in chain.ChainElements)
            foreach (var st in element.ChainElementStatus)
                if ((st.Status & fatal) != 0) return null;
        if (chain.ChainElements.Count == 0) return null;
        var top = chain.ChainElements[^1].Certificate;
        return top.SubjectName.RawData.AsSpan().SequenceEqual(top.IssuerName.RawData) ? top.Thumbprint : null;
    }

    /// <summary>Firma Authenticode embebida: tabla de certificados del PE (directorio de seguridad, entrada 4).</summary>
    internal static SignedCms? ReadPeSignature(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var br = new BinaryReader(fs);
        if (fs.Length < 0x100) return null;
        fs.Position = 0x3C;
        long lfanew = br.ReadUInt32();
        if (lfanew < 0x40 || lfanew > fs.Length - 0x100) return null;
        fs.Position = lfanew;
        if (br.ReadUInt32() != 0x00004550) return null; // "PE\0\0"
        fs.Position = lfanew + 24;
        long dataDirs = br.ReadUInt16() switch { 0x10b => lfanew + 24 + 96, 0x20b => lfanew + 24 + 112, _ => -1 };
        if (dataDirs < 0 || dataDirs + 5 * 8 > fs.Length) return null;
        fs.Position = dataDirs + 4 * 8;
        long offset = br.ReadUInt32();
        long size = br.ReadUInt32();
        if (offset == 0 || size < 8 || size > 16 * 1024 * 1024 || offset + size > fs.Length) return null;
        fs.Position = offset;
        long length = br.ReadUInt32();
        br.ReadUInt16(); // revisión
        if (br.ReadUInt16() != 2 || length <= 8 || length > size) return null; // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        return DecodeCms(br.ReadBytes((int)(length - 8)));
    }

    /// <summary>Decodifica un PKCS#7 ignorando el relleno que puede seguir al DER (la tabla se alinea a 8 bytes).</summary>
    internal static SignedCms? DecodeCms(byte[] blob)
    {
        if (blob.Length < 4 || blob[0] != 0x30) return null;
        int lenBytes = blob[1] < 0x80 ? 0 : blob[1] & 0x7F;
        if (lenBytes > 4 || blob.Length < 2 + lenBytes) return null;
        long len = lenBytes == 0 ? blob[1] : 0;
        for (int i = 0; i < lenBytes; i++) len = (len << 8) | blob[2 + i];
        long total = 2 + lenBytes + len;
        if (total > blob.Length) return null;
        var cms = new SignedCms();
        cms.Decode(total == blob.Length ? blob : blob.AsSpan(0, (int)total).ToArray());
        return cms;
    }
}
