using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Demiurge.Core.Model;
using Demiurge.Core.Util;

namespace Demiurge.Core.Storage;

/// <summary>
/// Persistencia SQLite: snapshots completos (para el diff), findings, caché de reputación,
/// respuestas del usuario, allowlist y registro de acciones reversibles.
/// </summary>
public sealed class DemiurgeDb
{
    private readonly string _connectionString;

    public static readonly JsonSerializerOptions Json = new()
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };

    public DemiurgeDb(string? path = null)
    {
        path ??= DemiurgePaths.Database;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = path, Cache = SqliteCacheMode.Shared }.ToString();
        Migrate();
    }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        using var pragma = c.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";
        pragma.ExecuteNonQuery();
        return c;
    }

    private void Migrate()
    {
        using var c = Open();
        Exec(c, """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started TEXT NOT NULL, finished TEXT, type TEXT NOT NULL,
                app_version TEXT, feeds_version TEXT, verdict TEXT, score_max INTEGER,
                snapshot BLOB);
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                heuristic_id TEXT NOT NULL, entity_kind TEXT NOT NULL, entity_key TEXT NOT NULL, scoring_key TEXT NOT NULL,
                weight INTEGER NOT NULL, severity TEXT NOT NULL, attack_ids TEXT, explanation TEXT, raw TEXT);
            CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);
            CREATE TABLE IF NOT EXISTS entities (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                kind TEXT NOT NULL, key TEXT NOT NULL, name TEXT, data TEXT,
                PRIMARY KEY (scan_id, kind, key));
            CREATE TABLE IF NOT EXISTS reputation_cache (
                hash TEXT NOT NULL, source TEXT NOT NULL, verdict TEXT NOT NULL, family TEXT, detections INTEGER,
                fetched TEXT NOT NULL, PRIMARY KEY (hash, source));
            CREATE TABLE IF NOT EXISTS user_answers (
                entity_key TEXT NOT NULL, question_id TEXT NOT NULL, answer TEXT NOT NULL, date TEXT NOT NULL,
                PRIMARY KEY (entity_key, question_id));
            CREATE TABLE IF NOT EXISTS allowlist (
                entity_key TEXT PRIMARY KEY, display_name TEXT, note TEXT, date TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS finding_state (
                heuristic_id TEXT NOT NULL, entity_key TEXT NOT NULL, state TEXT NOT NULL, date TEXT NOT NULL,
                PRIMARY KEY (heuristic_id, entity_key));
            CREATE TABLE IF NOT EXISTS actions (
                id TEXT PRIMARY KEY, date TEXT NOT NULL, type TEXT NOT NULL, target TEXT NOT NULL,
                description TEXT, backup TEXT, reverted INTEGER NOT NULL DEFAULT 0);
            """);
    }

    private static void Exec(SqliteConnection c, string sql, params (string, object?)[] args)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    // ---------------- Scans ----------------

    public long SaveScan(ScanSnapshot s)
    {
        using var c = Open();
        using var tx = c.BeginTransaction();

        using (var cmd = c.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO scans(started, finished, type, app_version, feeds_version, verdict, score_max, snapshot)
                VALUES ($started, $finished, $type, $app, $feeds, $verdict, $score, $snap);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("$started", s.Scan.Started.ToString("O"));
            cmd.Parameters.AddWithValue("$finished", (object?)s.Scan.Finished?.ToString("O") ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$type", s.Scan.Type.ToString());
            cmd.Parameters.AddWithValue("$app", s.Scan.AppVersion);
            cmd.Parameters.AddWithValue("$feeds", s.Scan.FeedsVersion);
            cmd.Parameters.AddWithValue("$verdict", s.Verdict.ToString());
            cmd.Parameters.AddWithValue("$score", s.Scan.ScoreMax);
            cmd.Parameters.AddWithValue("$snap", Compress(JsonSerializer.SerializeToUtf8Bytes(s, Json)));
            s.Scan.Id = (long)cmd.ExecuteScalar()!;
        }

        using (var cmd = c.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO findings(id, scan_id, heuristic_id, entity_kind, entity_key, scoring_key, weight, severity, attack_ids, explanation, raw)
                VALUES ($id, $scan, $h, $kind, $key, $sk, $w, $sev, $att, $exp, $raw)
                """;
            var p = new Dictionary<string, SqliteParameter>();
            foreach (var n in new[] { "$id", "$scan", "$h", "$kind", "$key", "$sk", "$w", "$sev", "$att", "$exp", "$raw" })
                p[n] = cmd.Parameters.Add(n, SqliteType.Text);
            foreach (var f in s.Findings)
            {
                p["$id"].Value = $"{s.Scan.Id}:{f.Id}";
                p["$scan"].Value = s.Scan.Id;
                p["$h"].Value = f.HeuristicId;
                p["$kind"].Value = f.EntityKind.ToString();
                p["$key"].Value = f.EntityKey;
                p["$sk"].Value = f.ScoringKey;
                p["$w"].Value = f.Weight;
                p["$sev"].Value = f.Severity.ToString();
                p["$att"].Value = string.Join(",", f.AttackIds);
                p["$exp"].Value = f.Explanation;
                p["$raw"].Value = f.RawData.ToJsonString();
                cmd.ExecuteNonQuery();
            }
        }

        using (var cmd = c.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT OR IGNORE INTO entities(scan_id, kind, key, name, data) VALUES ($scan, $kind, $key, $name, $data)";
            var pScan = cmd.Parameters.Add("$scan", SqliteType.Integer);
            var pKind = cmd.Parameters.Add("$kind", SqliteType.Text);
            var pKey = cmd.Parameters.Add("$key", SqliteType.Text);
            var pName = cmd.Parameters.Add("$name", SqliteType.Text);
            var pData = cmd.Parameters.Add("$data", SqliteType.Text);
            foreach (var e in s.AllEntities())
            {
                // Procesos y conexiones cambian en cada escaneo: no aportan al diff y engordan la base.
                if (e.Kind is EntityKind.Process or EntityKind.Connection or EntityKind.DnsQuery or EntityKind.ModuleLoad or EntityKind.Event) continue;
                pScan.Value = s.Scan.Id;
                pKind.Value = e.Kind.ToString();
                pKey.Value = e.Key;
                pName.Value = e.DisplayName;
                pData.Value = JsonSerializer.Serialize(e, e.GetType(), Json);
                cmd.ExecuteNonQuery();
            }
        }

        tx.Commit();
        return s.Scan.Id;
    }

    public List<ScanInfo> ListScans(int limit = 50)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, started, finished, type, app_version, feeds_version, verdict, score_max FROM scans ORDER BY id DESC LIMIT $l";
        cmd.Parameters.AddWithValue("$l", limit);
        using var r = cmd.ExecuteReader();
        var list = new List<ScanInfo>();
        while (r.Read())
        {
            list.Add(new ScanInfo
            {
                Id = r.GetInt64(0),
                Started = DateTimeOffset.Parse(r.GetString(1)),
                Finished = r.IsDBNull(2) ? null : DateTimeOffset.Parse(r.GetString(2)),
                Type = Enum.Parse<ScanType>(r.GetString(3)),
                AppVersion = r.IsDBNull(4) ? "" : r.GetString(4),
                FeedsVersion = r.IsDBNull(5) ? "" : r.GetString(5),
                Verdict = r.IsDBNull(6) ? null : Enum.Parse<GlobalVerdict>(r.GetString(6)),
                ScoreMax = r.IsDBNull(7) ? 0 : r.GetInt32(7),
            });
        }
        return list;
    }

    public ScanSnapshot? LoadScan(long? id = null)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = id is null
            ? "SELECT id, snapshot FROM scans WHERE type <> 'Vivo' ORDER BY id DESC LIMIT 1"
            : "SELECT id, snapshot FROM scans WHERE id = $id";
        if (id is not null) cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader();
        if (!r.Read() || r.IsDBNull(1)) return null;
        var snapshot = JsonSerializer.Deserialize<ScanSnapshot>(Decompress((byte[])r[1]), Json);
        // El blob se serializa antes de conocer el id autoincremental.
        if (snapshot is not null) snapshot.Scan.Id = r.GetInt64(0);
        return snapshot;
    }

    /// <summary>Escaneo anterior al indicado (para el diff).</summary>
    public ScanSnapshot? LoadPreviousScan(long beforeId)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id FROM scans WHERE id < $id AND type <> 'Vivo' ORDER BY id DESC LIMIT 1";
        cmd.Parameters.AddWithValue("$id", beforeId);
        return cmd.ExecuteScalar() is long prev ? LoadScan(prev) : null;
    }

    /// <summary>Retención: conservar los últimos N escaneos.</summary>
    public void Prune(int keep = 30)
    {
        using var c = Open();
        Exec(c, "DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT $k)", ("$k", keep));
    }

    // ---------------- Reputación ----------------

    public ReputationInfo? GetReputation(string hash, string source, TimeSpan ttl)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT verdict, family, detections, fetched FROM reputation_cache WHERE hash = $h AND source = $s";
        cmd.Parameters.AddWithValue("$h", hash.ToLowerInvariant());
        cmd.Parameters.AddWithValue("$s", source);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        var fetched = DateTimeOffset.Parse(r.GetString(3));
        if (DateTimeOffset.Now - fetched > ttl) return null;
        return new ReputationInfo
        {
            Source = source,
            Verdict = r.GetString(0),
            Family = r.IsDBNull(1) ? null : r.GetString(1),
            Detections = r.IsDBNull(2) ? null : r.GetInt32(2),
            Fetched = fetched,
        };
    }

    public void PutReputation(string hash, ReputationInfo rep)
    {
        using var c = Open();
        Exec(c, """
            INSERT INTO reputation_cache(hash, source, verdict, family, detections, fetched) VALUES ($h, $s, $v, $f, $d, $t)
            ON CONFLICT(hash, source) DO UPDATE SET verdict = $v, family = $f, detections = $d, fetched = $t
            """,
            ("$h", hash.ToLowerInvariant()), ("$s", rep.Source), ("$v", rep.Verdict), ("$f", rep.Family), ("$d", rep.Detections), ("$t", rep.Fetched.ToString("O")));
    }

    // ---------------- Usuario ----------------

    public void SaveAnswer(UserAnswer a)
    {
        using var c = Open();
        Exec(c, """
            INSERT INTO user_answers(entity_key, question_id, answer, date) VALUES ($k, $q, $a, $d)
            ON CONFLICT(entity_key, question_id) DO UPDATE SET answer = $a, date = $d
            """, ("$k", a.EntityKey), ("$q", a.QuestionId), ("$a", a.Answer), ("$d", a.Date.ToString("O")));
    }

    public List<UserAnswer> GetAnswers()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT entity_key, question_id, answer, date FROM user_answers";
        using var r = cmd.ExecuteReader();
        var list = new List<UserAnswer>();
        while (r.Read())
            list.Add(new UserAnswer { EntityKey = r.GetString(0), QuestionId = r.GetString(1), Answer = r.GetString(2), Date = DateTimeOffset.Parse(r.GetString(3)) });
        return list;
    }

    public void AddAllowlist(AllowlistEntry e)
    {
        using var c = Open();
        Exec(c, "INSERT OR REPLACE INTO allowlist(entity_key, display_name, note, date) VALUES ($k, $n, $note, $d)",
            ("$k", e.EntityKey), ("$n", e.DisplayName), ("$note", e.Note), ("$d", e.Date.ToString("O")));
    }

    public bool RemoveAllowlist(string key)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM allowlist WHERE entity_key = $k";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteNonQuery() > 0;
    }

    public List<AllowlistEntry> GetAllowlist()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT entity_key, display_name, note, date FROM allowlist";
        using var r = cmd.ExecuteReader();
        var list = new List<AllowlistEntry>();
        while (r.Read())
            list.Add(new AllowlistEntry
            {
                EntityKey = r.GetString(0),
                DisplayName = r.IsDBNull(1) ? null : r.GetString(1),
                Note = r.IsDBNull(2) ? null : r.GetString(2),
                Date = DateTimeOffset.Parse(r.GetString(3)),
            });
        return list;
    }

    public void SetFindingState(string heuristicId, string entityKey, FindingState state)
    {
        using var c = Open();
        Exec(c, """
            INSERT INTO finding_state(heuristic_id, entity_key, state, date) VALUES ($h, $k, $s, $d)
            ON CONFLICT(heuristic_id, entity_key) DO UPDATE SET state = $s, date = $d
            """, ("$h", heuristicId), ("$k", entityKey), ("$s", state.ToString()), ("$d", DateTimeOffset.Now.ToString("O")));
    }

    public Dictionary<string, FindingState> GetFindingStates()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT heuristic_id, entity_key, state FROM finding_state";
        using var r = cmd.ExecuteReader();
        var d = new Dictionary<string, FindingState>();
        while (r.Read()) d[$"{r.GetString(0)}|{r.GetString(1)}"] = Enum.Parse<FindingState>(r.GetString(2));
        return d;
    }

    // ---------------- Acciones ----------------

    public void SaveAction(ActionRecord a)
    {
        using var c = Open();
        Exec(c, """
            INSERT OR REPLACE INTO actions(id, date, type, target, description, backup, reverted)
            VALUES ($id, $d, $t, $target, $desc, $b, $r)
            """, ("$id", a.Id), ("$d", a.Date.ToString("O")), ("$t", a.Type), ("$target", a.Target), ("$desc", a.Description),
            ("$b", a.Backup), ("$r", a.Reverted ? 1 : 0));
    }

    public List<ActionRecord> GetActions(int limit = 200)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, date, type, target, description, backup, reverted FROM actions ORDER BY date DESC LIMIT $l";
        cmd.Parameters.AddWithValue("$l", limit);
        using var r = cmd.ExecuteReader();
        var list = new List<ActionRecord>();
        while (r.Read())
            list.Add(new ActionRecord
            {
                Id = r.GetString(0),
                Date = DateTimeOffset.Parse(r.GetString(1)),
                Type = r.GetString(2),
                Target = r.GetString(3),
                Description = r.IsDBNull(4) ? "" : r.GetString(4),
                Backup = r.IsDBNull(5) ? null : r.GetString(5),
                Reverted = r.GetInt32(6) != 0,
            });
        return list;
    }

    // ---------------- helpers ----------------

    private static byte[] Compress(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var gz = new BrotliStream(ms, CompressionLevel.Optimal)) gz.Write(data);
        return ms.ToArray();
    }

    private static byte[] Decompress(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var br = new BrotliStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        br.CopyTo(output);
        return output.ToArray();
    }
}

public sealed class ActionRecord
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Date { get; set; } = DateTimeOffset.Now;
    public string Type { get; set; } = "";
    public string Target { get; set; } = "";
    public string Description { get; set; } = "";
    /// <summary>JSON con lo necesario para revertir.</summary>
    public string? Backup { get; set; }
    public bool Reverted { get; set; }
}
