using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.Channels;

namespace FileGuardian.Core;

/// <summary>
/// The capture engine from the original Program.cs, without any console
/// dependency. One instance runs once: call <see cref="RunAsync"/>, cancel
/// the token to stop, and await the returned task for the drain to finish.
/// </summary>
public sealed class GuardianEngine
{
    private readonly GuardianOptions _options;
    private readonly ICaptureFilter? _filter;
    private readonly SemaphoreSlim _commitLock = new(1, 1);

    // Digests already stored per path this session; guarded by _commitLock.
    private readonly Dictionary<string, HashSet<string>> _storedDigests = new(PathSafety.PathComparer);
    private readonly ConcurrentDictionary<string, FileFingerprint> _lastCaptured =
        new(PathSafety.PathComparer);

    private readonly object _mirrorLock = new();
    private readonly Dictionary<string, CaptureMetadata> _latestByMirror = new(PathSafety.PathComparer);
    private readonly Dictionary<string, CaptureMetadata> _pendingMirrors = new(PathSafety.PathComparer);

    private CaptureIndexWriter? _index;
    private string _rootName = "";
    private int _started;
    private readonly ConcurrentDictionary<string, FileFingerprint> _observed = new(PathSafety.PathComparer);
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task Ready => _ready.Task;
    public string SessionId { get; } = Guid.NewGuid().ToString("N");
    private Channel<CaptureRecord>? _policyQueue;
    private long _queueDrops;
    private long _openMisses;
    private long _acquired;
    private long _pinned;
    private int _secureLinkWarned;
    private string? _linksDir;
    private Channel<CaptureRequest>? _captureQueue;
    private CancellationTokenSource? _stopSource;
    private int _rescanRequested;
    private int _fatalWatcherError;
    public long AcquiredHandleCount => Interlocked.Read(ref _acquired);
    public long QueueDropCount => Interlocked.Read(ref _queueDrops);
    public long OpenMissCount => Interlocked.Read(ref _openMisses);

    /// <summary>Files whose data is currently pinned by an evidence-store hard link.</summary>
    public long SecuredLinkCount => Interlocked.Read(ref _pinned);

    public GuardianEngine(GuardianOptions options, ICaptureFilter? filter = null)
    {
        options.Validate();
        _options = options;
        _filter = filter;
    }

    /// <summary>Raised on engine threads; handlers must be fast and must not throw.</summary>
    public event EventHandler<LogEntry>? LogEmitted;

    /// <summary>Raised after a capture is recorded in the index and published.</summary>
    public event EventHandler<CaptureRecord>? CaptureCommitted;

    public string? MonitorDirectory { get; private set; }
    public string? BackupDirectory { get; private set; }

    public static (string Monitor, string Backup) ResolveDirectories(GuardianOptions options) =>
        (PathSafety.NormalizeDirectory(options.MonitorDirectory),
         PathSafety.NormalizeDirectory(options.BackupDirectory ?? AppPaths.DefaultBackupDirectory));

    public async Task<GuardianExitReason> RunAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _started, 1) != 0)
            throw new InvalidOperationException("A GuardianEngine instance can only run once.");

        if (!PathSafety.IsSupportedPlatform)
        {
            Log(GuardianLogLevel.Error, "Unsupported operating system.");
            return GuardianExitReason.Failed;
        }

        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var abortWorker = new CancellationTokenSource();

        try
        {
            var (monitor, backup) = ResolveDirectories(_options);

            if (!Directory.Exists(monitor))
                throw new DirectoryNotFoundException($"Monitor directory does not exist: {monitor}");

            if (PathSafety.Overlaps(monitor, backup))
                throw new ArgumentException("Monitor and backup directories must not overlap.");

            PathSafety.EnsureNoReparsePoints(monitor);

            Directory.CreateDirectory(backup);
            PathSafety.EnsureNoReparsePoints(backup);

            MonitorDirectory = monitor;
            BackupDirectory = backup;

            _index = CaptureIndexWriter.Acquire(backup);
            await OpenStoreAsync(monitor, backup, stop.Token);

            var queue = Channel.CreateBounded<CaptureRequest>(
                new BoundedChannelOptions(_options.QueueCapacity)
                {
                    SingleReader = false,
                    SingleWriter = false,
                    FullMode = BoundedChannelFullMode.Wait,
                    AllowSynchronousContinuations = false
                });

            _linksDir = CaptureLayout.LinksDirectory(backup);
            _captureQueue = queue;
            _stopSource = stop;

            // Inventory only. Existing content is not evidence from this session.
            Log(GuardianLogLevel.Info, "Preparing session baseline (metadata only). Do not launch the sample yet.");
            await ScanAsync(monitor, null, stop.Token);


            using var watcher = new FileSystemWatcher(monitor)
            {
                Filter = "*",
                IncludeSubdirectories = true,
                NotifyFilter =
                    NotifyFilters.FileName |
                    NotifyFilters.DirectoryName |
                    NotifyFilters.LastWrite |
                    NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
                EnableRaisingEvents = false
            };

            watcher.Created += (_, e) =>
            {
                NotifyChanged(e.FullPath);
                Interlocked.Exchange(ref _rescanRequested, 1);
            };

            watcher.Changed += (_, e) => NotifyChanged(e.FullPath);

            watcher.Renamed += (_, e) =>
            {
                NotifyChanged(e.FullPath);

                // A moved directory can contain files that do not each
                // produce a separate creation event.
                Interlocked.Exchange(ref _rescanRequested, 1);
            };
            watcher.Deleted += (sender, e) => _observed.TryRemove(e.FullPath, out _);

            // A deletion notification cannot supply missing file contents.
            // Existing captures remain available under their capture IDs.

            watcher.Error += (_, e) =>
            {
                Exception error = e.GetException();

                Log(GuardianLogLevel.Error, $"Watcher error: {error.Message}");
                Interlocked.Exchange(ref _rescanRequested, 1);

                if (error is not InternalBufferOverflowException)
                {
                    Interlocked.Exchange(ref _fatalWatcherError, 1);
                    stop.Cancel();
                }
            };

            _policyQueue = Channel.CreateBounded<CaptureRecord>(128);
            using var policyStop = new CancellationTokenSource();
            Task policyWorker = RunPolicyAsync(_policyQueue.Reader, policyStop.Token);
            Task[] workers = Enumerable.Range(0, _options.WorkerCount)
                .Select(_ => Task.Run(() => RunWorkerAsync(queue.Reader, monitor, backup, abortWorker.Token)))
                .ToArray();

            async Task RunScannerAsync()
            {
                using var timer = new PeriodicTimer(_options.RescanInterval);
                long reportedDrops = 0;

                try
                {
                    do
                    {
                        // Metadata-only reconciliation detects missed changes;
                        // it never queues the whole unchanged directory tree.
                        if (Interlocked.Exchange(ref _rescanRequested, 0) != 0)
                            Log(GuardianLogLevel.Debug, "Reconciling metadata after directory activity or event/queue loss.");
                        await ScanAsync(monitor, queue.Writer, stop.Token);

                        RetryPendingMirrors(backup);
                        long drops = QueueDropCount;
                        if (drops != reportedDrops)
                        {
                            reportedDrops = drops;
                            Log(GuardianLogLevel.Warn, $"Acquisition queue saturated: {drops} dropped requests. " +
                                "Reconciliation can recover only files that still exist; short-lived artifacts may be lost.");
                        }
                    }
                    while (await timer.WaitForNextTickAsync(stop.Token));
                }
                catch (OperationCanceledException) when (stop.IsCancellationRequested)
                {
                }
                catch (Exception ex)
                {
                    Log(GuardianLogLevel.Error, $"Scanner failed: {ex.Message}");
                    Interlocked.Exchange(ref _fatalWatcherError, 1);
                    stop.Cancel();
                }
            }

            watcher.EnableRaisingEvents = true;
            if (_options.CaptureExistingFiles)
                _observed.Clear();
            Task scanner = RunScannerAsync();

            Log(GuardianLogLevel.Info, $"Monitoring: {monitor}");
            Log(GuardianLogLevel.Info, $"Captures: {backup}");
            if (_options.DenyDeleteWhileOpen)
                Log(GuardianLogLevel.Info, "Delete sharing withheld while artifacts are open; samples can observe this.");
            Log(GuardianLogLevel.Info, "Best-effort capture only; rapid deletion can beat capture.");
            Log(GuardianLogLevel.Info, $"Armed. Session {SessionId}; " +
                (_options.CaptureExistingFiles
                    ? "explicit existing-file collection enabled, plus new and modified artifacts."
                    : "capturing new and modified artifacts, not a whole-folder backup."));
            _ready.TrySetResult();

            try
            {
                await Task.Delay(Timeout.Infinite, stop.Token);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
            }

            watcher.EnableRaisingEvents = false;

            await scanner;
            queue.Writer.TryComplete();

            Log(GuardianLogLevel.Info,
                $"Draining queued captures; timeout: {_options.DrainTimeout.TotalSeconds:0} seconds.");
            abortWorker.CancelAfter(_options.DrainTimeout);

            await Task.WhenAll(workers);
            _policyQueue.Writer.TryComplete();
            policyStop.Cancel();
            await policyWorker;

            bool timedOut = abortWorker.IsCancellationRequested;

            if (timedOut)
                Log(GuardianLogLevel.Warn, "Shutdown timeout; queued work was abandoned.");

            RetryPendingMirrors(backup);
            Log(GuardianLogLevel.Info,
                $"Session {SessionId}: queue drops={Interlocked.Read(ref _queueDrops)}; " +
                $"file-open misses={Interlocked.Read(ref _openMisses)}; inode-pins={Interlocked.Read(ref _pinned)}. " +
                "These counters are not a complete count of lost artifacts.");

            if (Volatile.Read(ref _fatalWatcherError) != 0)
                return GuardianExitReason.WatcherFault;

            return timedOut ? GuardianExitReason.DrainTimedOut : GuardianExitReason.Stopped;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return GuardianExitReason.Stopped;
        }
        catch (Exception ex)
        {
            Log(GuardianLogLevel.Error, ex.Message);
            return GuardianExitReason.Failed;
        }
        finally
        {
            _ready.TrySetCanceled();
            _captureQueue = null;
            _stopSource = null;
            _index?.Dispose();
            _index = null;
        }
    }

    /// <summary>
    /// The watcher callback path. Every step here directly decides whether a
    /// short-lived artifact survives: pin the data (one hard-link syscall) and
    /// open a handle, synchronously, before any logging, hashing, copying or
    /// plugins. Everything heavier happens in the copy workers.
    /// </summary>
    internal void NotifyChanged(string path)
    {
        Channel<CaptureRequest>? queue = _captureQueue;
        CancellationTokenSource? stop = _stopSource;
        string? monitor = MonitorDirectory;
        if (queue is null || stop is null || monitor is null || stop.IsCancellationRequested)
            return;

        CaptureRequest? request = TryAcquire(path, monitor, CaptureTrigger.Watcher);
        if (request is null)
            return;
        if (!queue.Writer.TryWrite(request))
        {
            request.Dispose();
            Interlocked.Increment(ref _queueDrops);
            Interlocked.Exchange(ref _rescanRequested, 1);
        }
    }

    internal CaptureRequest? TryAcquire(string path, string monitor, CaptureTrigger trigger)
    {
        FileStream? source = null;
        string? secured = null;
        DateTime written = default;
        try
        {
            path = Path.GetFullPath(path);
            if (!PathSafety.IsWithin(monitor, path) || string.Equals(path, monitor, PathSafety.PathComparison))
                return null;
            PathSafety.EnsureNoReparsePoints(path);
            if ((File.GetAttributes(path) & FileAttributes.Directory) != 0)
                return null;
            written = File.GetLastWriteTimeUtc(path);

            // Pin the data first: one hard-link syscall. From this point,
            // deleting the original name cannot destroy the bytes; the copy
            // worker reads them whenever it is scheduled.
            if (_options.SecureOnAcquire)
                secured = TrySecureInode(path);

            // DenyDeleteWhileOpen withholds delete sharing, so marking the
            // file for deletion (and rename-away) fails while our handle is
            // open. Enforced on Windows; opt-in, see GuardianOptions.
            FileShare share = FileShare.ReadWrite;
            if (!_options.DenyDeleteWhileOpen)
                share |= FileShare.Delete;

            source = new FileStream(path, FileMode.Open, FileAccess.Read, share,
                _options.BufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            Interlocked.Increment(ref _acquired);
            return new CaptureRequest(path, trigger) { Source = source, SecuredLinkPath = secured, LastWriteUtc = written };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            source?.Dispose();
            Interlocked.Increment(ref _openMisses);

            if (secured is null)
            {
                // No handle and no pinned data: the artifact can still be lost.
                // Sharing violations may clear on a later event or rescan tick.
                return null;
            }

            // The direct open failed (sharing violation, vanished name), but
            // the data is pinned. The worker reopens through our link.
            return new CaptureRequest(path, trigger) { SecuredLinkPath = secured, LastWriteUtc = written };
        }
    }

    private string? TrySecureInode(string path)
    {
        if (_linksDir is null)
            return null;
        try
        {
            string link = Path.Combine(_linksDir, Guid.NewGuid().ToString("N"));
            if (CaptureLayout.TryCreateHardLink(path, link))
            {
                Interlocked.Increment(ref _pinned);
                return link;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }

        if (Interlocked.Exchange(ref _secureLinkWarned, 1) == 0)
        {
            Log(GuardianLogLevel.Warn,
                "Instant data pinning unavailable: hard links need the evidence folder on the same filesystem " +
                "(same NTFS volume on Windows) as the monitored folder. Falling back to handle-only acquisition; " +
                "fast deletion can still beat capture.");
        }

        return null;
    }

    private async Task RunPolicyAsync(ChannelReader<CaptureRecord> reader, CancellationToken token)
    {
        try
        {
            await foreach (var record in reader.ReadAllAsync(token))
                await RunFilterAsync(record.Metadata.OriginalPath, record.Metadata.RelativePath,
                    record.Metadata.CapturedLength, token).AsTask().WaitAsync(token);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }

    /// <summary>
    /// Recovers the evidence store. Session baselining is separate; historical
    /// content hashes do not decide what belongs to the current session.
    /// </summary>
    private async Task OpenStoreAsync(string monitor, string backup, CancellationToken token)
    {
        void Warn(string m) => Log(GuardianLogLevel.Warn, m);

        await CaptureStore.RecoverAsync(_index!, Warn, token);
        _rootName = CaptureLayout.GetOrAddRootName(backup, monitor);

        IndexSnapshot snapshot = CaptureIndex.Read(backup, Warn);
        string rootPrefix = _rootName + "/";

        int repaired = 0;
        lock (_mirrorLock)
        {
            foreach (var (mirror, c) in snapshot.LatestByMirror)
            {
                if (!mirror.StartsWith(rootPrefix, PathSafety.PathComparison))
                    continue;

                _latestByMirror[mirror] = c;

                // A crash between publishing a version and refreshing its
                // latest copy leaves the mirror behind; put it right.
                try
                {
                    if (!File.Exists(CaptureLayout.Resolve(backup, mirror)) &&
                        File.Exists(new CaptureRecord(c, backup).ContentPath) &&
                        CaptureStore.UpdateMirror(backup, c, null, Warn) == CaptureStore.MirrorResult.Updated)
                        repaired++;
                }
                catch (InvalidDataException ex)
                {
                    Warn(ex.Message);
                }
            }
        }

        Log(GuardianLogLevel.Info,
            $"Evidence index: {snapshot.Captures.Count} historical capture(s)" +
            (repaired > 0 ? $"; restored {repaired} latest cop(ies)." : "."));

        int legacy = CaptureStore.CountLegacy(backup);
        if (legacy > 0)
        {
            Log(GuardianLogLevel.Info,
                $"{legacy} capture(s) in the old one-folder-per-capture format. " +
                "Convert them from the Captures tab or with: FileGuardian.exe migrate");
        }
    }

    private void RetryPendingMirrors(string backup)
    {
        lock (_mirrorLock)
        {
            if (_pendingMirrors.Count == 0)
                return;

            foreach (var (mirror, capture) in _pendingMirrors.ToList())
            {
                // Only the newest version belongs in the mirror.
                if (!_latestByMirror.TryGetValue(mirror, out var latest) || latest.CaptureId != capture.CaptureId)
                {
                    _pendingMirrors.Remove(mirror);
                    continue;
                }

                if (CaptureStore.UpdateMirror(backup, capture, null, null) != CaptureStore.MirrorResult.Retry)
                    _pendingMirrors.Remove(mirror);
            }
        }
    }

    private void PublishMirror(string backup, CaptureMetadata capture)
    {
        lock (_mirrorLock)
        {
            // Parallel workers can finish out of order: an older capture must
            // never overwrite the latest copy of a newer one.
            if (_latestByMirror.TryGetValue(capture.MirrorPath!, out CaptureMetadata? newer) &&
                newer.StartedUtc > capture.StartedUtc)
            {
                return;
            }

            _latestByMirror.TryGetValue(capture.MirrorPath!, out CaptureMetadata? previous);
            _latestByMirror[capture.MirrorPath!] = capture;
            _pendingMirrors.Remove(capture.MirrorPath!);

            CaptureStore.MirrorResult result = CaptureStore.UpdateMirror(
                backup, capture, previous, m => Log(GuardianLogLevel.Debug, m));

            if (result == CaptureStore.MirrorResult.Retry)
                _pendingMirrors[capture.MirrorPath!] = capture;
            else if (result == CaptureStore.MirrorResult.Skipped)
                Log(GuardianLogLevel.Warn,
                    $"Latest copy not updated (name conflict in the backup tree); the version is kept: {capture.StoredPath}");
        }
    }

    private async Task RunWorkerAsync(
        ChannelReader<CaptureRequest> reader,
        string monitor,
        string backup,
        CancellationToken token)
    {
        try
        {
            await foreach (CaptureRequest request in reader.ReadAllAsync(token))
            {
                using (request)
                try
                {
                    await CaptureAsync(request, monitor, backup, token);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Log(GuardianLogLevel.Error, $"Capture failed for {request.Path}: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        finally
        {
            while (reader.TryRead(out var abandoned))
                abandoned.Dispose();
        }
    }

    private async Task CaptureAsync(
        CaptureRequest request,
        string monitor,
        string backup,
        CancellationToken token)
    {
        string path = Path.GetFullPath(request.Path);
        int bufferSize = _options.BufferSize;
        long maxFileBytes = _options.MaxFileBytes;

        if (!PathSafety.IsWithin(monitor, path) ||
            string.Equals(monitor, path, PathSafety.PathComparison))
        {
            throw new InvalidDataException("Event path is outside the monitored directory.");
        }

        DateTimeOffset startedUtc = DateTimeOffset.UtcNow;
        // The pathname may already have been deleted or renamed. Read the
        // handle acquired at event time, or reopen through the pinned link;
        // never reopen the original pathname here.
        FileStream? source = request.Source;
        bool ownSource = false;
        if (source is null)
        {
            if (request.SecuredLinkPath is null)
                throw new InvalidDataException("Missing acquisition handle.");
            // The data is pinned, so waiting costs nothing: a sharing
            // violation on the original usually clears within moments.
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    source = new FileStream(request.SecuredLinkPath, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete, bufferSize,
                        FileOptions.Asynchronous | FileOptions.SequentialScan);
                    break;
                }
                catch (Exception ex) when (attempt < 6 &&
                                           ex is IOException or UnauthorizedAccessException)
                {
                    await Task.Delay(50 * (1 << (attempt - 1)), token);
                }
            }

            ownSource = true;
        }

        if (!source.CanSeek)
            throw new InvalidDataException("Non-seekable sources are not supported.");

        long initialLength = source.Length;

        if (initialLength > maxFileBytes)
        {
            Log(GuardianLogLevel.Warn, $"Skipped oversized file: {path}");
            return;
        }

        if (initialLength == 0 && _options.SkipEmptyFiles)
            return;

        string relativePath = Path.GetRelativePath(monitor, path);
        var fingerprint = new FileFingerprint(initialLength, request.LastWriteUtc);

        if (request.Trigger == CaptureTrigger.Scan &&
            _options.SkipUnchangedOnRescan &&
            _lastCaptured.TryGetValue(path, out FileFingerprint previous) &&
            previous.SameMetadata(fingerprint))
        {
            return;
        }

        // Capture only the length observed when copying begins. This prevents a
        // continuously appended file from keeping the copy alive forever.
        long remaining = initialLength;
        long copied = 0;

        PathSafety.EnsureNoReparsePoints(backup);
        PathSafety.EnsureNoReparsePoints(CaptureLayout.StagingDirectory(backup));

        string captureId = $"{startedUtc:yyyyMMddTHHmmssfffffffZ}_{Guid.NewGuid():N}";
        string[] parts = CaptureLayout.SplitRelative(relativePath);
        string fileName = parts[^1];

        // The copy is written under .fileguardian/staging and only appears
        // in the visible tree once complete and recorded in the index.
        string stagingDirectory = Path.Combine(CaptureLayout.StagingDirectory(backup), captureId);
        bool committed = false;
        bool holdsCommitLock = false;

        Directory.CreateDirectory(stagingDirectory);

        try
        {
            string contentPath = Path.Combine(stagingDirectory, fileName);
            string digest;

            using (var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                await using (var destination = new FileStream(
                    contentPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    byte[] buffer = new byte[bufferSize];

                    while (remaining > 0)
                    {
                        token.ThrowIfCancellationRequested();

                        int requested = (int)Math.Min(buffer.Length, remaining);
                        int read = await source.ReadAsync(buffer.AsMemory(0, requested), token);

                        if (read == 0)
                            break;

                        if (copied > maxFileBytes - read)
                            throw new InvalidDataException("Capture exceeded the file-size limit.");

                        await destination.WriteAsync(buffer.AsMemory(0, read), token);
                        hasher.AppendData(buffer, 0, read);

                        copied += read;
                        remaining -= read;
                    }

                    await destination.FlushAsync(token);
                    destination.Flush(flushToDisk: true);
                }

                digest = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
            }

            // Copies run in parallel; naming, indexing and publication do not.
            // Two workers can finish the same content in the same second, and
            // both would otherwise pick the same version folder name.
            await _commitLock.WaitAsync(token);
            holdsCommitLock = true;

            if (_options.SkipIdenticalContent &&
                _storedDigests.TryGetValue(path, out HashSet<string>? stored) &&
                stored.Contains(digest))
            {
                // These bytes are already stored for this path in this session;
                // the finally block removes the duplicate copy.
                _lastCaptured[path] = fingerprint with { Sha256 = digest };
                Log(GuardianLogLevel.Debug, $"Unchanged content, not recaptured: {path}");
                return;
            }

            string versionParent = Path.Combine([CaptureLayout.VersionsDirectory(backup), _rootName, .. parts]);
            Directory.CreateDirectory(versionParent);
            PathSafety.EnsureNoReparsePoints(versionParent);

            string versionDirectory = CaptureStore.UniqueVersionDirectory(
                versionParent, CaptureLayout.VersionFolderName(startedUtc, digest));

            var metadata = new CaptureMetadata
            {
                CaptureId = captureId,
                SessionId = SessionId,
                ObservedUtc = request.ObservedUtc,
                Trigger = request.Trigger.ToString(),
                OriginalPath = path,
                RelativePath = relativePath,
                StartedUtc = startedUtc,
                CompletedUtc = DateTimeOffset.UtcNow,
                InitialLength = initialLength,
                CapturedLength = copied,
                ReachedInitialLength = copied == initialLength,
                Sha256 = digest,
                ContentFile = fileName,
                SourceLastWriteUtc = fingerprint.LastWriteUtc,
                MonitorDirectory = monitor,
                RootName = _rootName,
                StoredPath = CaptureLayout.ToStored(
                    Path.GetRelativePath(backup, Path.Combine(versionDirectory, fileName))),
                MirrorPath = CaptureLayout.ToStored(Path.Combine([_rootName, .. parts]))
            };

            token.ThrowIfCancellationRequested();
            PathSafety.EnsureNoReparsePoints(backup);

            // Record first, then publish with one directory rename. If the
            // process dies between the two, startup recovery finishes the
            // rename (staging is kept) or marks the entry discarded.
            await _index!.AppendAsync(new IndexEntry { Type = IndexEntry.CaptureType, Capture = metadata }, token);

            try
            {
                Directory.Move(stagingDirectory, versionDirectory);
                committed = true;
            }
            catch
            {
                try
                {
                    await _index.AppendAsync(
                        new IndexEntry { Type = IndexEntry.DiscardType, CaptureId = captureId }, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    Log(GuardianLogLevel.Warn, $"Could not record discarded capture {captureId}: {ex.Message}");
                }

                throw;
            }

            if (copied == initialLength)
                _lastCaptured[path] = fingerprint with { Sha256 = digest };

            var record = new CaptureRecord(metadata, backup);
            CaptureStore.TryMarkReadOnly(record.ContentPath, msg => Log(GuardianLogLevel.Warn, msg));
            PublishMirror(backup, metadata);
            if (!_storedDigests.TryGetValue(path, out HashSet<string>? digests))
                _storedDigests[path] = digests = new HashSet<string>(StringComparer.Ordinal);
            digests.Add(digest);

            _commitLock.Release();
            holdsCommitLock = false;

            Log(GuardianLogLevel.Capture,
                $"{metadata.MirrorPath}; bytes={copied}; SHA256={digest}; version={Path.GetFileName(versionDirectory)}");

            if (copied != initialLength)
            {
                Log(GuardianLogLevel.Warn,
                    $"Source shrank during capture: {path}. " +
                    "The saved capture is shorter than its initial length.");
            }

            RaiseCaptureCommitted(record);
            if (_filter is not null && !_policyQueue!.Writer.TryWrite(record))
                Log(GuardianLogLevel.Warn, "Advisory plugin queue full; artifact retained without policy evaluation.");
        }
        finally
        {
            if (holdsCommitLock)
                _commitLock.Release();

            if (ownSource)
                await source!.DisposeAsync();

            if (!committed)
            {
                try
                {
                    Directory.Delete(stagingDirectory, recursive: true);
                }
                catch (Exception ex)
                {
                    Log(GuardianLogLevel.Warn,
                        $"Could not remove partial capture {stagingDirectory}: {ex.Message}");
                }
            }
        }
    }

    private async ValueTask<bool> RunFilterAsync(
        string path, string relativePath, long length, CancellationToken token)
    {
        try
        {
            bool keep = await _filter!.ShouldCaptureAsync(
                new CaptureCandidate(path, relativePath, length), token);

            if (!keep)
                Log(GuardianLogLevel.Info, $"Plugin recommended exclusion after preservation; artifact retained: {path}");

            return keep;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Fail open: a broken filter must never cause silent data loss.
            Log(GuardianLogLevel.Warn, $"Post-preservation plugin policy failed for {path}; artifact retained: {ex.Message}");
            return true;
        }
    }

    private async Task ScanAsync(
        string monitor,
        ChannelWriter<CaptureRequest>? writer,
        CancellationToken token)
    {
        var directories = new Stack<string>();
        directories.Push(monitor);

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = false,
            IgnoreInaccessible = false,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false
        };

        while (directories.Count > 0)
        {
            await Task.Yield();
            token.ThrowIfCancellationRequested();
            string directory = directories.Pop();

            try
            {
                PathSafety.EnsureNoReparsePoints(directory);

                foreach (string entry in Directory.EnumerateFileSystemEntries(directory, "*", options))
                {
                    token.ThrowIfCancellationRequested();

                    try
                    {
                        FileAttributes attributes = File.GetAttributes(entry);

                        if ((attributes & FileAttributes.ReparsePoint) != 0)
                            continue;

                        if ((attributes & FileAttributes.Directory) != 0)
                            directories.Push(entry);
                        else
                        {
                            var info = new FileInfo(entry);
                            var fingerprint = new FileFingerprint(info.Length, info.LastWriteTimeUtc);
                            if (writer is null)
                            {
                                _observed[entry] = fingerprint;
                                continue;
                            }
                            if (_observed.TryGetValue(entry, out var previous) && previous.SameMetadata(fingerprint))
                                continue;
                            var request = TryAcquire(entry, monitor, CaptureTrigger.Scan);
                            if (request is null)
                                continue;
                            if (writer.TryWrite(request))
                                _observed[entry] = fingerprint;
                            else
                            {
                                request.Dispose();
                                Interlocked.Increment(ref _queueDrops);
                            }
                        }
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        Log(GuardianLogLevel.Warn, $"Could not scan entry {entry}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Log(GuardianLogLevel.Warn, $"Could not scan directory {directory}: {ex.Message}");
            }
        }
    }

    private void Log(GuardianLogLevel level, string message)
    {
        var entry = new LogEntry(DateTimeOffset.UtcNow, level, message);
        foreach (EventHandler<LogEntry> handler in LogEmitted?.GetInvocationList() ?? [])
        {
            try { handler(this, entry); }
            catch { /* An observer must never break capture. */ }
        }
    }

    private void RaiseCaptureCommitted(CaptureRecord record)
    {
        foreach (EventHandler<CaptureRecord> handler in CaptureCommitted?.GetInvocationList() ?? [])
        {
            try { handler(this, record); }
            catch (Exception ex) { Log(GuardianLogLevel.Warn, $"Capture observer failed: {ex.Message}"); }
        }
    }
}
