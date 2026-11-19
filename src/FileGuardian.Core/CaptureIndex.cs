using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FileGuardian.Core;

/// <summary>One line of .fileguardian/index.jsonl.</summary>
public sealed record IndexEntry
{
    public const string CaptureType = "capture";
    public const string AnalysisType = "analysis";
    public const string DiscardType = "discard";

    /// <summary>"capture", "analysis", or "discard" (capture never published).</summary>
    public required string Type { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CaptureMetadata? Capture { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CaptureId { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public StoredAnalysis? Analysis { get; init; }
}

/// <summary>Everything in the index, folded into lookups.</summary>
public sealed class IndexSnapshot
{
    /// <summary>Published captures in the order they were recorded.</summary>
    public List<CaptureMetadata> Captures { get; } = [];

    /// <summary>captureId -> pluginId -> newest result.</summary>
    public Dictionary<string, Dictionary<string, StoredAnalysis>> Analyses { get; } = new(StringComparer.Ordinal);

    /// <summary>Mirror path -> newest capture (by start time) shown there.</summary>
    public Dictionary<string, CaptureMetadata> LatestByMirror { get; } = new(PathSafety.PathComparer);

    /// <summary>Original source path -> newest capture of it.</summary>
    public Dictionary<string, CaptureMetadata> LatestBySource { get; } = new(PathSafety.PathComparer);

    public HashSet<string> Ids { get; } = new(StringComparer.Ordinal);

    public IReadOnlyList<StoredAnalysis> AnalysesFor(string captureId) =>
        Analyses.TryGetValue(captureId, out var byPlugin) ? byPlugin.Values.ToList() : [];

    public bool IsLatest(CaptureMetadata m) =>
        m.MirrorPath is not null &&
        LatestByMirror.TryGetValue(m.MirrorPath, out CaptureMetadata? latest) &&
        latest.CaptureId == m.CaptureId;
}

public static class CaptureIndex
{
    internal const int MaxLineBytes = 64 * 1024;

    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        MaxDepth = 16,
        WriteIndented = false
    };

    /// <summary>
    /// Reads the whole index. Safe while another process is appending: an
    /// incomplete last line is ignored. Unknown or damaged lines are skipped.
    /// </summary>
    public static IndexSnapshot Read(string backup, Action<string>? warn = null)
    {
        var snapshot = new IndexSnapshot();
        string path = CaptureLayout.IndexPath(backup);

        if (!File.Exists(path))
            return snapshot;

        PathSafety.EnsureNoReparsePoints(path);

        var captures = new Dictionary<string, CaptureMetadata>(StringComparer.Ordinal);
        var order = new List<string>();
        int damaged = 0;

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);
        using var reader = new StreamReader(stream, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false);

        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.Length == 0)
                continue;

            if (line.Length > MaxLineBytes)
            {
                damaged++;
                continue;
            }

            IndexEntry? entry;
            try
            {
                entry = JsonSerializer.Deserialize<IndexEntry>(line, Json);
            }
            catch (JsonException)
            {
                damaged++;
                continue;
            }

            switch (entry?.Type)
            {
                case IndexEntry.CaptureType when entry.Capture is { StoredPath: not null } c &&
                                                 CaptureStore.IsValidCaptureId(c.CaptureId):
                    if (captures.TryAdd(c.CaptureId, c))
                        order.Add(c.CaptureId);
                    break;

                case IndexEntry.DiscardType when entry.CaptureId is not null:
                    captures.Remove(entry.CaptureId);
                    break;

                case IndexEntry.AnalysisType when entry.CaptureId is not null && entry.Analysis is not null:
                    if (!snapshot.Analyses.TryGetValue(entry.CaptureId, out var byPlugin))
                        snapshot.Analyses[entry.CaptureId] = byPlugin = new(StringComparer.Ordinal);
                    byPlugin[entry.Analysis.PluginId] = entry.Analysis;
                    break;
            }
        }

        foreach (string id in order)
        {
            if (!captures.TryGetValue(id, out CaptureMetadata? c))
                continue;

            snapshot.Captures.Add(c);
            snapshot.Ids.Add(id);

            if (c.MirrorPath is not null &&
                (!snapshot.LatestByMirror.TryGetValue(c.MirrorPath, out var m) || c.StartedUtc >= m.StartedUtc))
                snapshot.LatestByMirror[c.MirrorPath] = c;

            if (!snapshot.LatestBySource.TryGetValue(c.OriginalPath, out var s) || c.StartedUtc >= s.StartedUtc)
                snapshot.LatestBySource[c.OriginalPath] = c;
        }

        if (damaged > 0)
            warn?.Invoke($"Skipped {damaged} unreadable line(s) in {CaptureLayout.IndexFile}.");

        return snapshot;
    }
}

/// <summary>
/// Appends to index.jsonl. One writer process per backup folder, enforced
/// with an exclusive lock file; within a process the writer is shared and
/// reference-counted so the engine and the plugin host can both use it.
/// </summary>
public sealed class CaptureIndexWriter : IDisposable
{
    private static readonly Dictionary<string, CaptureIndexWriter> Open = new(PathSafety.PathComparer);
    private static readonly object OpenLock = new();

    private readonly FileStream _lock;
    private readonly FileStream _index;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _refs;

    private CaptureIndexWriter(string backup, FileStream lockStream, FileStream index)
    {
        BackupDirectory = backup;
        _lock = lockStream;
        _index = index;
    }

    public string BackupDirectory { get; }

    /// <summary>Gets the shared writer for <paramref name="backup"/>; dispose to release.</summary>
    public static CaptureIndexWriter Acquire(string backup)
    {
        backup = PathSafety.NormalizeDirectory(backup);

        lock (OpenLock)
        {
            if (!Open.TryGetValue(backup, out CaptureIndexWriter? writer))
            {
                writer = OpenExclusive(backup);
                Open[backup] = writer;
            }

            writer._refs++;
            return writer;
        }
    }

    /// <summary>Bypasses the in-process cache; used directly only by tests.</summary>
    internal static CaptureIndexWriter OpenExclusive(string backup)
    {
        Directory.CreateDirectory(backup);
        PathSafety.EnsureNoReparsePoints(backup);

        string internalDir = CaptureLayout.InternalDirectory(backup);
        Directory.CreateDirectory(internalDir);
        Directory.CreateDirectory(CaptureLayout.StagingDirectory(backup));
        Directory.CreateDirectory(CaptureLayout.VersionsDirectory(backup));
        Directory.CreateDirectory(CaptureLayout.LinksDirectory(backup));
        PathSafety.EnsureNoReparsePoints(CaptureLayout.StagingDirectory(backup));
        PathSafety.EnsureNoReparsePoints(CaptureLayout.VersionsDirectory(backup));
        PathSafety.EnsureNoReparsePoints(CaptureLayout.LinksDirectory(backup));

        if (OperatingSystem.IsWindows())
        {
            try { File.SetAttributes(internalDir, File.GetAttributes(internalDir) | FileAttributes.Hidden); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        FileStream lockStream;
        try
        {
            lockStream = new FileStream(Path.Combine(internalDir, CaptureLayout.LockFile),
                FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException ex)
        {
            throw new IOException(
                $"The capture folder is in use by another FileGuardian process: {backup}", ex);
        }

        try
        {
            var index = new FileStream(CaptureLayout.IndexPath(backup), FileMode.OpenOrCreate,
                FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.None);

            // After a crash the last line can be incomplete; start on a fresh
            // line so the next entry is not glued onto the damaged one.
            if (index.Length > 0)
            {
                index.Seek(-1, SeekOrigin.End);
                if (index.ReadByte() != '\n')
                    index.WriteByte((byte)'\n');
            }

            index.Seek(0, SeekOrigin.End);
            return new CaptureIndexWriter(backup, lockStream, index);
        }
        catch
        {
            lockStream.Dispose();
            throw;
        }
    }

    public async Task AppendAsync(IndexEntry entry, CancellationToken token = default)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(entry, CaptureIndex.Json);
        if (json.Length > CaptureIndex.MaxLineBytes)
            throw new InvalidDataException("Index entry is too large.");

        await _gate.WaitAsync(token);
        try
        {
            ObjectDisposedException.ThrowIf(_refs <= 0, this);

            // A single write per line, flushed to disk, so a reader never
            // sees half of a committed entry followed by another entry.
            byte[] line = new byte[json.Length + 1];
            json.CopyTo(line, 0);
            line[^1] = (byte)'\n';

            _index.Seek(0, SeekOrigin.End);
            await _index.WriteAsync(line, CancellationToken.None);
            await _index.FlushAsync(CancellationToken.None);
            _index.Flush(flushToDisk: true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        lock (OpenLock)
        {
            if (_refs <= 0 || --_refs > 0)
                return;

            if (Open.TryGetValue(BackupDirectory, out var current) && ReferenceEquals(current, this))
                Open.Remove(BackupDirectory);
        }

        _gate.Wait();
        try
        {
            _index.Dispose();
            _lock.Dispose();
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>For <see cref="OpenExclusive"/> callers that bypass the cache.</summary>
    internal void AddRefForTest() => _refs++;
}
