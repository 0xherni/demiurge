using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Demiurge.Core.Enrichment;

/// <summary>Hashes en streaming (COL-07), cacheados por path + mtime + tamaño.</summary>
public static class FileHasher
{
    public sealed record Hashes(string Sha256, string Sha1, string Md5, long Size, DateTimeOffset Created, DateTimeOffset Modified);

    private static readonly ConcurrentDictionary<string, Hashes> Cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Límite para no colgar el escaneo con archivos gigantes.</summary>
    public static long MaxBytes { get; set; } = 512L * 1024 * 1024;

    public static Hashes? Compute(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return null;
            var cacheKey = $"{fi.FullName}|{fi.LastWriteTimeUtc.Ticks}|{fi.Length}";
            if (Cache.TryGetValue(cacheKey, out var cached)) return cached;
            if (fi.Length > MaxBytes) return null;

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
            using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            var buffer = new byte[1 << 16];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha256.AppendData(buffer, 0, read);
                sha1.AppendData(buffer, 0, read);
                md5.AppendData(buffer, 0, read);
            }
            var h = new Hashes(
                Convert.ToHexStringLower(sha256.GetHashAndReset()),
                Convert.ToHexStringLower(sha1.GetHashAndReset()),
                Convert.ToHexStringLower(md5.GetHashAndReset()),
                fi.Length, fi.CreationTimeUtc, fi.LastWriteTimeUtc);
            Cache[cacheKey] = h;
            return h;
        }
        catch
        {
            return null;
        }
    }
}
