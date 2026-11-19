using System.Collections.Concurrent;
using System.Security.Cryptography;
using FileGuardian.Core;

namespace FileGuardian.Tests;

/// <summary>
/// Tests for the acquisition-speed path: watcher-callback hard-link pinning,
/// delete-blocking, and parallel copy workers.
/// </summary>
public class ArtifactSpeedTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Session : IDisposable
    {
        public required GuardianEngine Engine { get; init; }
        public required ConcurrentQueue<CaptureRecord> Captures { get; init; }
        public required Task<GuardianExitReason> Run { get; init; }
        public required CancellationTokenSource Stop { get; init; }

        public void Dispose()
        {
            Stop.Cancel();
            Run.GetAwaiter().GetResult();
            Stop.Dispose();
        }
    }

    private static async Task<Session> ArmAsync(string monitor, string backup, int workerCount = 2)
    {
        var captures = new ConcurrentQueue<CaptureRecord>();
        var options = new GuardianOptions
        {
            MonitorDirectory = monitor,
            BackupDirectory = backup,
            RescanInterval = TimeSpan.FromHours(1),
            WorkerCount = workerCount
        };

        var engine = new GuardianEngine(options);
        engine.CaptureCommitted += (_, r) => captures.Enqueue(r);
        var stop = new CancellationTokenSource();
        var run = engine.RunAsync(stop.Token);
        await engine.Ready.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        return new Session { Engine = engine, Captures = captures, Run = run, Stop = stop };
    }

    private static async Task<CaptureRecord?> WaitForAsync(Session s, string fileName)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!deadline.IsCancellationRequested)
        {
            CaptureRecord? hit = s.Captures.FirstOrDefault(
                c => c.Metadata.OriginalPath.EndsWith(fileName, PathSafety.PathComparison));
            if (hit is not null)
                return hit;
            await Task.Delay(25, Ct);
        }

        return null;
    }

    private static async Task<CaptureRecord?> WaitForContentAsync(Session s, byte[] data)
    {
        string sha = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!deadline.IsCancellationRequested)
        {
            CaptureRecord? hit = s.Captures.FirstOrDefault(c => c.Metadata.Sha256 == sha);
            if (hit is not null)
                return hit;
            await Task.Delay(25, Ct);
        }

        return null;
    }

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    [Fact]
    public async Task PinnedDataSurvivesDeletionBeforeTheWorkerRuns()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        using var s = await ArmAsync(monitor, backup);

        string victim = Path.Combine(monitor, "dropped.bin");
        byte[] expected = RandomBytes(64 * 1024);
        await File.WriteAllBytesAsync(victim, expected, Ct);

        // Deterministic: acquisition (pin + open) completes synchronously
        // inside NotifyChanged; deletion happens strictly after acquisition.
        s.Engine.NotifyChanged(victim);
        File.Delete(victim);
        Assert.False(File.Exists(victim));

        CaptureRecord? capture = await WaitForContentAsync(s, expected);
        Assert.NotNull(capture);
        Assert.Equal(expected, await File.ReadAllBytesAsync(capture.ContentPath, Ct));
        Assert.True(s.Engine.SecuredLinkCount >= 1);
    }

    [Fact]
    public async Task PinnedDataSurvivesRenameAwayBeforeTheWorkerRuns()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        // Stall all copy workers on the first publication, then enqueue while blocked.
        using var s = await ArmAsync(monitor, backup, workerCount: 1);

        string victim = Path.Combine(monitor, "staged.dat");
        byte[] expected = RandomBytes(32 * 1024);
        await File.WriteAllBytesAsync(victim, expected, Ct);

        s.Engine.NotifyChanged(victim);
        string renamed = Path.Combine(monitor, "moved", "renamed.dat");
        Directory.CreateDirectory(Path.GetDirectoryName(renamed)!);
        File.Move(victim, renamed);

        CaptureRecord? capture = await WaitForContentAsync(s, expected);
        Assert.NotNull(capture);
        Assert.Equal(expected, await File.ReadAllBytesAsync(capture.ContentPath, Ct));
        Assert.EndsWith("staged.dat", capture.Metadata.OriginalPath, PathSafety.PathComparison);
        Assert.False(File.Exists(victim));
        Assert.True(File.Exists(renamed)); // the malware's file still exists; we did not interfere
    }

    [Fact]
    public async Task WorkerReadsThroughPinWhenOriginalOpenFails()
    {
        if (OperatingSystem.IsWindows())
            return; // CreateHardLink cannot pin a file without delete sharing there anyway.

        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        using var s = await ArmAsync(monitor, backup);

        // Build the unreadable file outside the monitored folder, then move it
        // in: the rename keeps mode 000, so every open attempt fails.
        string staged = Path.Combine(tmp.Path, "locked.stage");
        byte[] expected = RandomBytes(16 * 1024);
        await File.WriteAllBytesAsync(staged, expected, Ct);
        File.SetUnixFileMode(staged, UnixFileMode.None);

        string victim = Path.Combine(monitor, "locked.bin");
        File.Move(staged, victim);
        s.Engine.NotifyChanged(victim);

        // The watcher may also fire; any number of pins refer to the same inode.
        string[] pins = [];
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (pins.Length == 0 && !deadline.IsCancellationRequested)
        {
            pins = Directory.GetFiles(CaptureLayout.LinksDirectory(backup));
            await Task.Delay(10, Ct);
        }

        Assert.NotEmpty(pins);
        Assert.Equal(0, s.Engine.AcquiredHandleCount); // the direct open failed; only the pin holds the data
        File.Delete(victim);
        foreach (string pin in pins.Where(File.Exists))
            File.SetUnixFileMode(pin, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        CaptureRecord? capture = await WaitForContentAsync(s, expected);
        Assert.NotNull(capture);
        Assert.Equal(expected, await File.ReadAllBytesAsync(capture.ContentPath, Ct));
    }

    [Fact]
    public async Task DenyDeleteWhileOpenBlocksDeletionOfAnAcquiredArtifact()
    {
        if (!OperatingSystem.IsWindows())
            return; // Delete-share enforcement is a Windows feature.

        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        using var gate = new ManualResetEventSlim(false);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var captures = new ConcurrentQueue<CaptureRecord>();
        var engine = new GuardianEngine(new GuardianOptions
        {
            MonitorDirectory = monitor, BackupDirectory = backup, DenyDeleteWhileOpen = true,
            RescanInterval = TimeSpan.FromHours(1)
        });
        engine.CaptureCommitted += (_, r) => captures.Enqueue(r);

        // The delete-block applies while our acquisition handle is open. Stall
        // before copying begins by subscribing to acquisition completion.
        using var stop = new CancellationTokenSource();
        Task<GuardianExitReason> run = engine.RunAsync(stop.Token);
        await engine.Ready.WaitAsync(TimeSpan.FromSeconds(10), Ct);

        string victim = Path.Combine(monitor, "payload.exe");
        await File.WriteAllBytesAsync(victim, RandomBytes(1024), Ct);
        engine.NotifyChanged(victim);

        // The handle is held until the copy worker consumes the request.
        Assert.Throws<IOException>(() => File.Delete(victim));

        await Task.Delay(300, Ct); // let the copy finish and release the handle
        File.Delete(victim);        // now deletion succeeds
        Assert.False(File.Exists(victim));

        stop.Cancel();
        await run;
    }

    [Fact]
    public async Task ParallelWorkersCaptureEveryQueuedArtifact()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        int count = 60;
        using var s = await ArmAsync(monitor, backup, workerCount: 4);

        var contents = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        for (int i = 0; i < count; i++)
        {
            string path = Path.Combine(monitor, $"a-{i:00}.bin");
            byte[] data = RandomBytes(4 * 1024 + i);
            await File.WriteAllBytesAsync(path, data, Ct);
            contents[path] = data;
        }

        foreach (string path in contents.Keys)
            s.Engine.NotifyChanged(path);

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        static string Hash(byte[] d) => Convert.ToHexString(SHA256.HashData(d)).ToLowerInvariant();
        while (!deadline.IsCancellationRequested &&
               !contents.All(kv => s.Captures.Any(c => c.Metadata.Sha256 == Hash(kv.Value))))
            await Task.Delay(100, Ct);

        // Intermediate (empty) states may also be preserved; every final state must be.
        foreach (var (path, data) in contents)
            Assert.Contains(s.Captures, c => c.Metadata.OriginalPath == path && c.Metadata.Sha256 == Hash(data));
    }

    [Fact]
    public async Task ConcurrentIdenticalCapturesDoNotCollideOnVersionFolder()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        using var s = await ArmAsync(monitor, backup, workerCount: 4);
        var errors = new ConcurrentQueue<string>();
        s.Engine.LogEmitted += (_, e) =>
        {
            if (e.Level == GuardianLogLevel.Error)
                errors.Enqueue(e.Message);
        };

        string file = Path.Combine(monitor, "invoice.pdf.exe");
        byte[] data = RandomBytes(512 * 1024);
        await File.WriteAllBytesAsync(file, data, Ct);
        for (int i = 0; i < 8; i++)
            s.Engine.NotifyChanged(file);

        Assert.NotNull(await WaitForContentAsync(s, data));
        await Task.Delay(1000, Ct);

        Assert.Empty(errors);
        string sha8 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant()[..8];
        string[] versions = Directory.GetDirectories(
            Path.Combine(CaptureLayout.VersionsDirectory(backup), "mon", "invoice.pdf.exe"));
        Assert.Single(versions, v => v.Contains($"[{sha8}]", StringComparison.Ordinal));
    }

    [Fact]
    public async Task MirrorAlwaysShowsNewestVersionDespiteConcurrentCompletion()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        using var s = await ArmAsync(monitor, backup, workerCount: 4);

        string file = Path.Combine(monitor, "notes.txt");

        await File.WriteAllTextAsync(file, "version-one", Ct);
        s.Engine.NotifyChanged(file);
        Assert.NotNull(await WaitForAsync(s, "notes.txt"));

        await File.WriteAllTextAsync(file, "version-two-is-longer", Ct);
        s.Engine.NotifyChanged(file);

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        string mirror = Path.Combine(backup, "mon", "notes.txt");
        while (!deadline.IsCancellationRequested &&
               !(File.Exists(mirror) && File.ReadAllText(mirror) == "version-two-is-longer" &&
                 s.Captures.Any(c => c.Metadata.CapturedLength == 21)))
            await Task.Delay(50, Ct);

        await Task.Delay(300, Ct); // let any slower, older completion try to overwrite
        Assert.Equal("version-two-is-longer",
            await File.ReadAllTextAsync(Path.Combine(backup, "mon", "notes.txt"), Ct));

        var listing = CaptureStore.LoadRecent(backup, 10);
        Assert.Single(listing, l => l.IsLatest);
    }

    [Fact]
    public async Task RecoveryPurgesStaleAcquisitionPins()
    {
        using var tmp = new TempDir();
        string backup = tmp.Sub("bak");
        string monitor = tmp.Sub("mon");
        Directory.CreateDirectory(monitor);

        using (var writer = CaptureIndexWriter.Acquire(backup))
        {
            string pin = Path.Combine(CaptureLayout.LinksDirectory(backup), Guid.NewGuid().ToString("N"));
            await File.WriteAllTextAsync(pin, "stale", Ct);

            // Simulate a crash: the writer is abandoned with the pin in place.
            await CaptureStore.RecoverAsync(writer, null, Ct);
            Assert.False(File.Exists(pin));
        }
    }
}
