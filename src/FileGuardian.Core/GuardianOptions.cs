namespace FileGuardian.Core;

public sealed class GuardianOptions
{
    public required string MonitorDirectory { get; init; }

    /// <summary>Null means <see cref="AppPaths.DefaultBackupDirectory"/>.</summary>
    public string? BackupDirectory { get; init; }

    public long MaxFileBytes { get; init; } = 1024L * 1024 * 1024;
    public int QueueCapacity { get; init; } = 4096;
    public int BufferSize { get; init; } = 81920;
    public TimeSpan RescanInterval { get; init; } = TimeSpan.FromSeconds(2);
    public TimeSpan DrainTimeout { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Explicit forensic collection, not the default session behavior.</summary>
    public bool CaptureExistingFiles { get; init; }

    /// <summary>
    /// Avoid duplicate acquisition for metadata-identical scan candidates.
    /// Watcher change events bypass this check.
    /// </summary>
    public bool SkipUnchangedOnRescan { get; init; } = true;

    /// <summary>
    /// Behavior change from the console version: one write often raises
    /// several watcher events (Created + Changed x N). When the copied bytes
    /// hash to the same SHA-256 as the previous capture of the same path,
    /// the duplicate is discarded instead of published. No distinct content
    /// is ever dropped.
    /// </summary>
    public bool SkipIdenticalContent { get; init; } = true;

    /// <summary>
    /// Empty marker files can themselves be artifacts. Preserve them by
    /// default, even though creation can produce an empty intermediate capture.
    /// </summary>
    public bool SkipEmptyFiles { get; init; }

    /// <summary>
    /// Default on. In every acquisition the engine first creates a hard link
    /// to the file inside the evidence store: one syscall that pins the data,
    /// so deleting the original name can no longer destroy the bytes before a
    /// copy worker reads them. Fastest protection available to a user-mode
    /// process. Requires the evidence folder on the same filesystem as the
    /// monitored folder (same NTFS volume on Windows); falls back with one
    /// warning per session.
    /// </summary>
    public bool SecureOnAcquire { get; init; } = true;

    /// <summary>
    /// Opt-in. Withhold FILE_SHARE_DELETE when opening artifacts: marking the
    /// file for deletion (and rename-away) then fails while our handle is
    /// open, so the sample's DeleteFile reports a sharing violation. Enforced
    /// on Windows only, and it changes behavior the sample can observe and
    /// adapt to. Content can still be truncated via write access.
    /// </summary>
    public bool DenyDeleteWhileOpen { get; init; }

    /// <summary>Concurrent copy workers. Acquisition order is preserved on disk by version times.</summary>
    public int WorkerCount { get; init; } = Math.Min(4, Math.Max(2, Environment.ProcessorCount / 2));

    internal void Validate()
    {
        if (MaxFileBytes <= 0) throw new ArgumentOutOfRangeException(nameof(MaxFileBytes));
        if (QueueCapacity <= 0) throw new ArgumentOutOfRangeException(nameof(QueueCapacity));
        if (WorkerCount <= 0) throw new ArgumentOutOfRangeException(nameof(WorkerCount));
        if (BufferSize < 4096) throw new ArgumentOutOfRangeException(nameof(BufferSize));
        if (RescanInterval <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(RescanInterval));
        if (DrainTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(DrainTimeout));
    }
}

public enum GuardianExitReason
{
    /// <summary>Stopped on request and drained cleanly (exit code 0).</summary>
    Stopped,
    /// <summary>Watcher or scanner failed (exit code 1).</summary>
    WatcherFault,
    /// <summary>Drain timeout; queued work abandoned (exit code 1).</summary>
    DrainTimedOut,
    /// <summary>Validation or setup failed (exit code 1).</summary>
    Failed
}
