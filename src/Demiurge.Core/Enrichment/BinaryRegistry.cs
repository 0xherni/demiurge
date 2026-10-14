using System.Collections.Concurrent;
using System.Diagnostics;
using Demiurge.Core.Model;
using Demiurge.Core.Native;

namespace Demiurge.Core.Enrichment;

/// <summary>
/// Punto único donde los colectores registran binarios. Calcula hash (COL-07) y firma (COL-06),
/// ambos cacheados, y devuelve la clave de la entidad Binary.
/// </summary>
public sealed class BinaryRegistry
{
    private static readonly ConcurrentDictionary<string, SignatureInfo> SignatureCache = new(StringComparer.OrdinalIgnoreCase);

    private readonly ScanSnapshot _snapshot;
    private readonly ConcurrentDictionary<string, string> _pathToKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public BinaryRegistry(ScanSnapshot snapshot) => _snapshot = snapshot;

    public string? Register(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        string full;
        try { full = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path.Trim('"'))); }
        catch { return null; }

        if (_pathToKey.TryGetValue(full, out var existing)) return existing;

        var bin = new BinaryInfo { Path = full };
        var hashes = FileHasher.Compute(full);
        if (hashes is null)
        {
            bin.Exists = File.Exists(full);
        }
        else
        {
            bin.Sha256 = hashes.Sha256;
            bin.Sha1 = hashes.Sha1;
            bin.Md5 = hashes.Md5;
            bin.Size = hashes.Size;
            bin.Created = hashes.Created;
            bin.Modified = hashes.Modified;
        }

        if (bin.Exists)
        {
            var sigKey = bin.Sha256 ?? full;
            bin.Signature = SignatureCache.GetOrAdd(sigKey, _ => WinTrust.Verify(full));
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(full);
                bin.ProductName = NullIfEmpty(vi.ProductName);
                bin.CompanyName = NullIfEmpty(vi.CompanyName);
                bin.FileDescription = NullIfEmpty(vi.FileDescription);
            }
            catch
            {
                // sin version info
            }
        }

        var key = bin.Key;
        lock (_lock)
        {
            // El mismo hash puede estar en varias rutas: conservamos la primera como path principal.
            if (!_snapshot.Binaries.ContainsKey(key)) _snapshot.Binaries[key] = bin;
        }
        _pathToKey[full] = key;
        return key;
    }

    private static string? NullIfEmpty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
