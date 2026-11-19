using System.Text.Json;
using System.Text.RegularExpressions;

namespace FileGuardian.Core;

/// <summary>Analysis result as persisted by the host (never by the plugin).</summary>
public sealed record StoredAnalysis(
    string PluginId,
    string PluginName,
    string Verdict,
    string? Summary,
    IReadOnlyList<string> Tags,
    IReadOnlyDictionary<string, string> Fields,
    DateTimeOffset CompletedUtc);

public static partial class CaptureStore
{
    private const int MaxMetadataBytes = 64 * 1024;
    private const string AnalysisFolder = "analysis";

    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        MaxDepth = 16
    };

    [GeneratedRegex(@"^\d{8}T\d{13}Z_[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex CaptureIdPattern();

    [GeneratedRegex(@"^[a-z0-9][a-z0-9._-]{0,63}$", RegexOptions.CultureInvariant)]
    internal static partial Regex PluginIdPattern();

    public static bool IsValidCaptureId(string id) => CaptureIdPattern().IsMatch(id);

    /// <summary>A capture as listed in the GUI.</summary>
    public sealed record Listing(CaptureRecord Record, IReadOnlyList<StoredAnalysis> Analyses, bool IsLatest);

    /// <summary>Newest captures first, with their plugin results.</summary>
    public static IReadOnlyList<Listing> LoadRecent(string backupDirectory, int maxCount, Action<string>? warn = null)
    {
        if (!Directory.Exists(backupDirectory))
            return [];

        PathSafety.EnsureNoReparsePoints(backupDirectory);
        IndexSnapshot snapshot = CaptureIndex.Read(backupDirectory, warn);

        return snapshot.Captures
            .OrderByDescending(c => c.StartedUtc)
            .Take(maxCount)
            .Select(c => new Listing(new CaptureRecord(c, backupDirectory), snapshot.AnalysesFor(c.CaptureId), snapshot.IsLatest(c)))
            .ToList();
    }

    public static async Task WriteAnalysisAsync(
        CaptureRecord record, StoredAnalysis analysis, CancellationToken token)
    {
        if (!PluginIdPattern().IsMatch(analysis.PluginId))
            throw new ArgumentException("Invalid plugin id.");

        using CaptureIndexWriter writer = CaptureIndexWriter.Acquire(record.BackupDirectory);
        await writer.AppendAsync(new IndexEntry
        {
            Type = IndexEntry.AnalysisType,
            CaptureId = record.Metadata.CaptureId,
            Analysis = analysis
        }, token);
    }

    // ------------------------------------------------------------------ mirror

    public enum MirrorResult
    {
        Updated,
        /// <summary>Temporarily blocked (file open elsewhere); try again later.</summary>
        Retry,
        /// <summary>Permanently impossible (a folder has the same name); the version is still kept.</summary>
        Skipped
    }

    /// <summary>
    /// Points the exact-name copy at <paramref name="capture"/>'s version file.
    /// The version file is the record of truth; failing here never loses data.
    /// </summary>
    /// <param name="previous">Capture currently shown at the mirror path, if any.</param>
    public static MirrorResult UpdateMirror(
        string backup, CaptureMetadata capture, CaptureMetadata? previous, Action<string>? warn = null)
    {
        if (capture.MirrorPath is null || capture.StoredPath is null)
            return MirrorResult.Skipped;

        string version = CaptureLayout.Resolve(backup, capture.StoredPath);
        string mirror = CaptureLayout.Resolve(backup, capture.MirrorPath);
        string directory = Path.GetDirectoryName(mirror)!;
        string? previousVersion = null;

        try
        {
            if (previous?.StoredPath is not null)
                previousVersion = CaptureLayout.Resolve(backup, previous.StoredPath);
        }
        catch (InvalidDataException) { }

        try
        {
            // The source tree can change shape over time (a file "a" later
            // becomes a folder "a"). The newest version is always kept under
            // .fileguardian/versions, so the mirror just skips that path.
            if (ExistsAsFileOnPath(backup, directory))
            {
                warn?.Invoke($"Latest copy not updated; a file blocks the folder path: {capture.MirrorPath}");
                return MirrorResult.Skipped;
            }

            Directory.CreateDirectory(directory);
            PathSafety.EnsureNoReparsePoints(directory);

            if (Directory.Exists(mirror))
            {
                warn?.Invoke($"Latest copy not updated; a folder has the same name: {capture.MirrorPath}");
                return MirrorResult.Skipped;
            }

            if (File.Exists(mirror) && (File.GetAttributes(mirror) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException($"Refusing to replace a link: {mirror}");

            string temp = Path.Combine(directory, $".fg-{Guid.NewGuid():N}.tmp");
            try
            {
                if (!CaptureLayout.TryCreateHardLink(version, temp))
                {
                    File.Copy(version, temp);
                    TryMarkReadOnly(temp);
                }

                // Windows refuses to replace a read-only file. The mirror is a
                // hard link to the previous version, so clearing the flag also
                // clears it on that version; it is restored below.
                if (OperatingSystem.IsWindows() && File.Exists(mirror))
                    File.SetAttributes(mirror, File.GetAttributes(mirror) & ~FileAttributes.ReadOnly);

                File.Move(temp, mirror, overwrite: true);
                return MirrorResult.Updated;
            }
            finally
            {
                if (File.Exists(temp))
                {
                    try
                    {
                        File.SetAttributes(temp, FileAttributes.Normal);
                        File.Delete(temp);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                }

                if (OperatingSystem.IsWindows())
                {
                    if (previousVersion is not null && File.Exists(previousVersion))
                        TryMarkReadOnly(previousVersion);
                    if (File.Exists(mirror))
                        TryMarkReadOnly(mirror);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warn?.Invoke($"Latest copy of {capture.MirrorPath} not updated yet: {ex.Message}");
            return MirrorResult.Retry;
        }
    }

    private static bool ExistsAsFileOnPath(string backup, string directory)
    {
        for (string? d = directory;
             d is not null && PathSafety.IsWithin(backup, d) && !string.Equals(d, backup, PathSafety.PathComparison);
             d = Path.GetDirectoryName(d))
        {
            if (File.Exists(d))
                return true;
        }

        return false;
    }

    // ------------------------------------------------------------------ crash recovery

    /// <summary>
    /// Finishes or removes work interrupted by a crash. The worker writes the
    /// index entry immediately before publishing a version, so at most the
    /// newest entry can lack its file. Caller holds <paramref name="writer"/>.
    /// </summary>
    public static async Task RecoverAsync(CaptureIndexWriter writer, Action<string>? warn, CancellationToken token)
    {
        string backup = writer.BackupDirectory;
        IndexSnapshot snapshot = CaptureIndex.Read(backup, warn);
        var byId = snapshot.Captures.ToDictionary(c => c.CaptureId, StringComparer.Ordinal);
        string staging = CaptureLayout.StagingDirectory(backup);

        foreach (string dir in Directory.EnumerateDirectories(staging))
        {
            string id = Path.GetFileName(dir);
            try
            {
                if (byId.TryGetValue(id, out CaptureMetadata? c) && !File.Exists(new CaptureRecord(c, backup).ContentPath))
                {
                    string versionDir = Path.GetDirectoryName(new CaptureRecord(c, backup).ContentPath)!;
                    Directory.CreateDirectory(Path.GetDirectoryName(versionDir)!);
                    Directory.Move(dir, versionDir);
                    warn?.Invoke($"Recovered interrupted capture: {c.MirrorPath}");
                    continue;
                }

                ClearReadOnly(dir);
                Directory.Delete(dir, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                warn?.Invoke($"Could not clean up staging folder {id}: {ex.Message}");
            }
        }

        if (snapshot.Captures.Count > 0)
        {
            CaptureMetadata last = snapshot.Captures[^1];
            if (!File.Exists(new CaptureRecord(last, backup).ContentPath))
                await writer.AppendAsync(new IndexEntry { Type = IndexEntry.DiscardType, CaptureId = last.CaptureId }, token);
        }

        // Leftover acquisition links pin data that no worker will ever read.
        string linksDir = CaptureLayout.LinksDirectory(backup);
        if (!Directory.Exists(linksDir))
            return;
        foreach (string leftover in Directory.EnumerateFiles(linksDir))
        {
            try { File.Delete(leftover); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                warn?.Invoke($"Could not remove acquisition pin {leftover}: {ex.Message}");
            }
        }
    }

    // ------------------------------------------------------------------ old format (schema 1-2)

    private static bool IsLegacyFolderName(string name) =>
        IsValidCaptureId(name) || name.StartsWith(".partial-", StringComparison.Ordinal);

    /// <summary>Old per-capture folders ("20261107T…Z_…") at the top of the backup folder.</summary>
    public static int CountLegacy(string backup)
    {
        if (!Directory.Exists(backup))
            return 0;

        return Directory.EnumerateDirectories(backup)
            .Count(d => IsValidCaptureId(Path.GetFileName(d)));
    }

    public sealed record MigrationResult(int Converted, int Failed, int AlreadyConverted);

    /// <summary>
    /// Converts schema 1-2 capture folders into the current layout: content
    /// moves (not copies) into versions/, metadata and plugin results go into
    /// the index, the newest version of each file becomes the latest copy, and
    /// the old folder is removed. Safe to re-run after an interruption.
    /// </summary>
    public static async Task<MigrationResult> MigrateLegacyAsync(
        string backup, Action<string>? log, CancellationToken token)
    {
        backup = PathSafety.NormalizeDirectory(backup);
        using CaptureIndexWriter writer = CaptureIndexWriter.Acquire(backup);
        await RecoverAsync(writer, log, token);

        IndexSnapshot snapshot = CaptureIndex.Read(backup, log);
        int converted = 0, failed = 0, already = 0;
        var touched = new HashSet<string>(PathSafety.PathComparer);

        var folders = Directory.EnumerateDirectories(backup)
            .Select(d => (Path: d, Name: Path.GetFileName(d)))
            .Where(d => IsLegacyFolderName(d.Name))
            .OrderBy(d => d.Name, StringComparer.Ordinal)
            .ToList();

        foreach (var (folder, name) in folders)
        {
            token.ThrowIfCancellationRequested();

            try
            {
                PathSafety.EnsureNoReparsePoints(folder);

                // Interrupted captures from the old engine never published.
                if (name.StartsWith(".partial-", StringComparison.Ordinal))
                {
                    ClearReadOnly(folder);
                    Directory.Delete(folder, recursive: true);
                    continue;
                }

                CaptureMetadata old = ReadMetadata(folder)
                    ?? throw new InvalidDataException("Missing metadata.json.");
                if (old.CaptureId != name)
                    throw new InvalidDataException("Capture ID does not match its folder.");

                string oldContent = Path.Combine(folder, old.ContentFile);

                if (snapshot.Ids.Contains(old.CaptureId))
                {
                    CaptureMetadata existing = snapshot.Captures.First(c => c.CaptureId == old.CaptureId);
                    string target = new CaptureRecord(existing, backup).ContentPath;
                    if (!File.Exists(target) && File.Exists(oldContent))
                        MoveIntoVersions(oldContent, target);

                    RemoveLegacyFolder(folder);
                    already++;
                    continue;
                }

                string monitor = DeriveMonitor(old);
                string root = CaptureLayout.GetOrAddRootName(backup, monitor);
                string[] parts = CaptureLayout.SplitRelative(old.RelativePath);
                string fileName = parts[^1];

                string versionDir = UniqueVersionDirectory(
                    Path.Combine([CaptureLayout.VersionsDirectory(backup), root, .. parts]),
                    CaptureLayout.VersionFolderName(old.StartedUtc, old.Sha256));

                var metadata = old with
                {
                    SchemaVersion = 3,
                    MonitorDirectory = monitor,
                    RootName = root,
                    ContentFile = fileName,
                    StoredPath = CaptureLayout.ToStored(Path.GetRelativePath(backup, Path.Combine(versionDir, fileName))),
                    MirrorPath = CaptureLayout.ToStored(Path.Combine([root, .. parts])),
                    Migrated = true
                };

                await writer.AppendAsync(new IndexEntry { Type = IndexEntry.CaptureType, Capture = metadata }, token);
                foreach (StoredAnalysis a in ReadLegacyAnalyses(folder))
                {
                    await writer.AppendAsync(new IndexEntry
                    {
                        Type = IndexEntry.AnalysisType, CaptureId = metadata.CaptureId, Analysis = a
                    }, token);
                }

                MoveIntoVersions(oldContent, Path.Combine(versionDir, fileName));
                RemoveLegacyFolder(folder);
                touched.Add(metadata.MirrorPath!);
                converted++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or JsonException)
            {
                failed++;
                log?.Invoke($"Could not convert {name}: {ex.Message}");
            }
        }

        // Refresh the latest copies of every file that gained a version.
        snapshot = CaptureIndex.Read(backup, log);
        foreach (string mirror in touched)
        {
            if (snapshot.LatestByMirror.TryGetValue(mirror, out CaptureMetadata? latest))
                UpdateMirror(backup, latest, null, log);
        }

        return new MigrationResult(converted, failed, already);
    }

    internal static string UniqueVersionDirectory(string parent, string name)
    {
        string candidate = Path.Combine(parent, name);
        for (int n = 2; Directory.Exists(candidate) || File.Exists(candidate); n++)
            candidate = Path.Combine(parent, $"{name} ({n})");
        return candidate;
    }

    private static void MoveIntoVersions(string source, string target)
    {
        string dir = Path.GetDirectoryName(target)!;
        Directory.CreateDirectory(dir);
        PathSafety.EnsureNoReparsePoints(dir);
        File.Move(source, target);
        TryMarkReadOnly(target);
    }

    private static string DeriveMonitor(CaptureMetadata old)
    {
        string original = Path.GetFullPath(old.OriginalPath);
        string rel = old.RelativePath;

        if (!original.EndsWith(rel, PathSafety.PathComparison) ||
            original.Length <= rel.Length ||
            original[^(rel.Length + 1)] is not ('/' or '\\'))
            throw new InvalidDataException("Original and relative paths do not agree.");

        return PathSafety.NormalizeDirectory(original[..^rel.Length]);
    }

    private static void RemoveLegacyFolder(string folder)
    {
        ClearReadOnly(folder);
        Directory.Delete(folder, recursive: true);
    }

    private static void ClearReadOnly(string folder)
    {
        foreach (string f in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
        {
            try { File.SetAttributes(f, FileAttributes.Normal); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>Reads a schema 1-2 metadata.json.</summary>
    public static CaptureMetadata? ReadMetadata(string captureDirectory)
    {
        string path = Path.Combine(captureDirectory, "metadata.json");
        byte[] bytes = ReadCapped(path, MaxMetadataBytes);
        CaptureMetadata? metadata = JsonSerializer.Deserialize<CaptureMetadata>(bytes, ReadOptions);

        // metadata.json is data on disk; do not let it redirect us elsewhere.
        if (metadata is null || Path.GetFileName(metadata.ContentFile) != metadata.ContentFile)
            throw new InvalidDataException("Invalid capture metadata.");

        return metadata;
    }

    private static IReadOnlyList<StoredAnalysis> ReadLegacyAnalyses(string captureDirectory)
    {
        string folder = Path.Combine(captureDirectory, AnalysisFolder);
        var list = new List<StoredAnalysis>();

        if (!Directory.Exists(folder))
            return list;

        foreach (string file in Directory.EnumerateFiles(folder, "*.json"))
        {
            try
            {
                StoredAnalysis? a = JsonSerializer.Deserialize<StoredAnalysis>(
                    ReadCapped(file, MaxMetadataBytes), ReadOptions);
                if (a is not null && PluginIdPattern().IsMatch(a.PluginId))
                    list.Add(a);
            }
            catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException)
            {
            }
        }

        return list;
    }

    /// <summary>
    /// Out-of-process analyzers read the captured copy. Marking it read-only
    /// is a guard against accidental modification, not a security boundary
    /// against code running as the same user.
    /// </summary>
    public static void TryMarkReadOnly(string path, Action<string>? warn = null)
    {
        try
        {
            if (OperatingSystem.IsWindows())
                File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
            else
                File.SetUnixFileMode(path, UnixFileMode.UserRead);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warn?.Invoke($"Could not mark capture read-only: {ex.Message}");
        }
    }

    internal static byte[] ReadCapped(string path, int maxBytes)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > maxBytes)
            throw new InvalidDataException($"File exceeds {maxBytes} bytes: {Path.GetFileName(path)}");

        byte[] bytes = new byte[stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }
}
