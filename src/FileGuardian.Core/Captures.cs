namespace FileGuardian.Core;

/// <summary>
/// One capture. Schema 3 entries live in .fileguardian/index.jsonl; schema
/// 1-2 were per-capture metadata.json files (read only for conversion).
/// </summary>
public sealed record CaptureMetadata
{
    public int SchemaVersion { get; init; } = 3;
    public required string CaptureId { get; init; }
    public required string OriginalPath { get; init; }
    public required string RelativePath { get; init; }
    public DateTimeOffset StartedUtc { get; init; }
    public DateTimeOffset CompletedUtc { get; init; }
    public long InitialLength { get; init; }
    public long CapturedLength { get; init; }
    public bool ReachedInitialLength { get; init; }
    public required string Sha256 { get; init; }
    public string ContentFile { get; init; } = "content.bin";
    public string Consistency { get; init; } = "Live-file capture; not a filesystem snapshot.";
    public DateTime? SourceLastWriteUtc { get; init; }

    /// <summary>Schema 3: monitored folder this capture came from.</summary>
    public string? MonitorDirectory { get; init; }

    /// <summary>Schema 3: top-level folder name in the backup ("Downloads").</summary>
    public string? RootName { get; init; }

    /// <summary>Schema 3: immutable version file, '/'-separated, relative to the backup folder.</summary>
    public string? StoredPath { get; init; }

    /// <summary>Schema 3: latest-copy location, '/'-separated, relative to the backup folder.</summary>
    public string? MirrorPath { get; init; }

    /// <summary>Schema 3: true when converted from a schema 1-2 capture folder.</summary>
    public bool Migrated { get; init; }
    public string? SessionId { get; init; }
    public string? Trigger { get; init; }
    public DateTimeOffset? ObservedUtc { get; init; }
}

public sealed record CaptureRecord(CaptureMetadata Metadata, string BackupDirectory)
{
    /// <summary>The immutable captured copy. Plugins analyze this file.</summary>
    public string ContentPath => CaptureLayout.Resolve(
        BackupDirectory, Metadata.StoredPath ?? throw new InvalidDataException("Capture has no stored path."));

    /// <summary>Where the newest version of this file appears with its exact name.</summary>
    public string? MirrorPath => Metadata.MirrorPath is null ? null : CaptureLayout.Resolve(BackupDirectory, Metadata.MirrorPath);

    /// <summary>"Downloads/tools/setup.exe": the path as shown in the backup tree.</summary>
    public string DisplayPath => Metadata.MirrorPath ?? Metadata.RelativePath;
}

/// <summary>Legacy plugin policy input. Invoked only after preservation.</summary>
public sealed record CaptureCandidate(string FullPath, string RelativePath, long Length);

public interface ICaptureFilter
{
    /// <summary>
    /// Advisory policy only, after durable publication. False never deletes
    /// evidence. Kept for compatibility with existing plugin protocols.
    /// </summary>
    ValueTask<bool> ShouldCaptureAsync(CaptureCandidate candidate, CancellationToken token);
}

public enum CaptureTrigger
{
    Watcher,
    Scan,
    Manual
}

internal sealed record CaptureRequest(string Path, CaptureTrigger Trigger) : IDisposable
{
    public FileStream? Source { get; init; }

    /// <summary>
    /// Hard link created in the watcher callback (same filesystem as the
    /// evidence store). It pins the file's data, so deleting the original
    /// name cannot destroy the bytes before the copy worker reads them.
    /// </summary>
    public string? SecuredLinkPath { get; init; }

    public DateTimeOffset ObservedUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTime LastWriteUtc { get; init; }

    public void Dispose()
    {
        Source?.Dispose();
        if (SecuredLinkPath is not null)
        {
            try { File.Delete(SecuredLinkPath); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}

internal readonly record struct FileFingerprint(long Length, DateTime LastWriteUtc, string? Sha256 = null)
{
    public bool SameMetadata(FileFingerprint other) =>
        Length == other.Length && LastWriteUtc == other.LastWriteUtc;
}
