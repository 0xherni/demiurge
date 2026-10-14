using System.Security.Cryptography.X509Certificates;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Collectors;

/// <summary>
/// COL-20: certificados raíz instalados (LocalMachine y el store Root de cada usuario).
/// El cruce con la lista authroot de Microsoft (TI-13) lo hace el RulesEngine.
/// </summary>
public sealed class CertificateCollector : ICollector
{
    public string Id => "COL-20";
    public string Name => "Certificados raíz";
    public int Order => 20;

    public Task<CollectorResult> CollectAsync(ScanContext ctx, CancellationToken ct)
    {
        var list = new List<CertificateInfo>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(X509Certificate2 c, string store)
        {
            if (!seen.Add(store + "|" + c.Thumbprint)) return;
            list.Add(new CertificateInfo
            {
                Subject = c.GetNameInfo(X509NameType.SimpleName, false) is { Length: > 0 } n ? n : c.Subject,
                Issuer = c.Issuer,
                Thumbprint = c.Thumbprint,
                Store = store,
                NotBefore = c.NotBefore,
                NotAfter = c.NotAfter,
            });
        }

        foreach (var loc in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            try
            {
                using var store = new X509Store(StoreName.Root, loc);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                foreach (var c in store.Certificates) using (c) Add(c, loc == StoreLocation.LocalMachine ? "LocalMachine\\Root" : $"{Environment.UserName}\\Root");
            }
            catch
            {
                // store no disponible
            }
        }

        // Stores Root de otros usuarios (el servicio corre como SYSTEM).
        foreach (var (_, user, root) in UserProfiles.UserHives())
        {
            using (root)
            {
                using var certs = root.OpenSubKey(@"Software\Microsoft\SystemCertificates\Root\Certificates");
                if (certs is null) continue;
                foreach (var thumb in certs.GetSubKeyNames())
                {
                    using var k = certs.OpenSubKey(thumb);
                    if (k?.GetValue("Blob") is not byte[] blob) continue;
                    var der = ExtractCertFromBlob(blob);
                    if (der is null) continue;
                    try
                    {
                        using var c = X509CertificateLoader.LoadCertificate(der);
                        Add(c, $"{user}\\Root");
                    }
                    catch
                    {
                        // blob inválido
                    }
                }
            }
        }

        ctx.Snapshot.AddRange(ctx.Snapshot.Certificates, list);
        return Task.FromResult(CollectorResult.Of(list.Count));
    }

    /// <summary>El blob del registro es una lista de propiedades {id, reservado, largo, datos}; la 32 es el certificado DER.</summary>
    internal static byte[]? ExtractCertFromBlob(byte[] blob)
    {
        int i = 0;
        while (i + 12 <= blob.Length)
        {
            int id = BitConverter.ToInt32(blob, i);
            int len = BitConverter.ToInt32(blob, i + 8);
            if (len < 0 || i + 12 + len > blob.Length) return null;
            if (id == 32) return blob.AsSpan(i + 12, len).ToArray();
            i += 12 + len;
        }
        return null;
    }
}
