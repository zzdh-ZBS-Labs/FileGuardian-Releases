using System.Collections.Concurrent;
using FileGuardian.Core;

namespace FileGuardian.Tests;

public class ArtifactSessionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task UntilAsync(Func<bool> predicate)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!predicate())
            await Task.Delay(10, deadline.Token);
    }

    [Fact]
    public async Task BaselineDoesNotCopyButAModifiedExistingFileIsEvidence()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        for (int i = 0; i < 30; i++)
            await File.WriteAllTextAsync(Path.Combine(monitor, $"existing-{i}.txt"), "baseline", Ct);
        var captures = new ConcurrentQueue<CaptureRecord>();
        var engine = new GuardianEngine(new GuardianOptions
        {
            MonitorDirectory = monitor, BackupDirectory = backup,
            RescanInterval = TimeSpan.FromMilliseconds(40)
        });
        engine.CaptureCommitted += (_, r) => captures.Enqueue(r);
        using var stop = new CancellationTokenSource();
        Task run = engine.RunAsync(stop.Token);
        try
        {
            await engine.Ready.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            await Task.Delay(250, Ct); // several reconciliation passes
            Assert.Empty(captures);
            Assert.Equal(0, engine.AcquiredHandleCount);
            await File.WriteAllTextAsync(Path.Combine(monitor, "existing-0.txt"), "modified", Ct);
            await UntilAsync(() => !captures.IsEmpty);
            Assert.All(captures, r =>
            {
                Assert.Equal("existing-0.txt", r.Metadata.RelativePath);
                Assert.Equal(engine.SessionId, r.Metadata.SessionId);
                Assert.NotNull(r.Metadata.ObservedUtc);
                Assert.NotNull(r.Metadata.Trigger);
            });
        }
        finally
        {
            stop.Cancel();
            await run;
        }
    }

    [Fact]
    public async Task WatcherPinsNextArtifactEvenWhenPublicationWorkerIsBlocked()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim(false);
        var captured = new ConcurrentQueue<CaptureRecord>();
        var engine = new GuardianEngine(new GuardianOptions
        {
            MonitorDirectory = monitor, BackupDirectory = backup,
            RescanInterval = TimeSpan.FromHours(1)
        });
        int blocked = 0;
        engine.CaptureCommitted += (_, r) =>
        {
            captured.Enqueue(r);
            if (Interlocked.Exchange(ref blocked, 1) == 0)
            {
                entered.TrySetResult();
                release.Wait(TimeSpan.FromSeconds(10));
            }
        };
        using var stop = new CancellationTokenSource();
        Task run = engine.RunAsync(stop.Token);
        try
        {
            await engine.Ready.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            string prepared = Path.Combine(tmp.Path, "first");
            await File.WriteAllTextAsync(prepared, "first artifact", Ct);
            File.Move(prepared, Path.Combine(monitor, "first.bin"));
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            await Task.Delay(150, Ct); // let notifications for the first file finish
            long before = engine.AcquiredHandleCount;
            string dropped = Path.Combine(monitor, "ephemeral.exe");
            await File.WriteAllTextAsync(prepared, "short-lived payload bytes", Ct);
            File.Move(prepared, dropped);
            await UntilAsync(() => engine.AcquiredHandleCount > before);
            File.Delete(dropped); // delete while copy worker is still stalled
            release.Set();
            await UntilAsync(() => captured.Any(c => c.Metadata.RelativePath == "ephemeral.exe"));
            var record = captured.First(c => c.Metadata.RelativePath == "ephemeral.exe");
            Assert.False(File.Exists(dropped));
            Assert.Equal("short-lived payload bytes", await File.ReadAllTextAsync(record.ContentPath, Ct));
        }
        finally
        {
            release.Set();
            stop.Cancel();
            await run;
        }
    }

    private sealed class HangingPolicy : ICaptureFilter
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<bool> ShouldCaptureAsync(CaptureCandidate c, CancellationToken token)
        {
            Entered.TrySetResult();
            await Task.Delay(Timeout.Infinite, token);
            return false;
        }
    }

    [Fact]
    public async Task HangingLegacyFilterDoesNotDelayAcquisitionOrDiscardEvidence()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        var policy = new HangingPolicy();
        var captured = new ConcurrentQueue<CaptureRecord>();
        var engine = new GuardianEngine(new GuardianOptions
        {
            MonitorDirectory = monitor, BackupDirectory = backup
        }, policy);
        engine.CaptureCommitted += (_, r) => captured.Enqueue(r);
        using var stop = new CancellationTokenSource();
        Task run = engine.RunAsync(stop.Token);
        try
        {
            await engine.Ready.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(monitor, "one.exe"), "one", Ct);
            await policy.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            Assert.Contains(captured, c => c.Metadata.RelativePath == "one.exe");
            await File.WriteAllTextAsync(Path.Combine(monitor, "two.exe"), "two", Ct);
            await UntilAsync(() => captured.Any(c => c.Metadata.RelativePath == "two.exe"));
        }
        finally
        {
            stop.Cancel();
            await run.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task QueueSaturationIsCountedInsteadOfSilentlyLosingHandles()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim(false);
        var engine = new GuardianEngine(new GuardianOptions
        {
            MonitorDirectory = monitor, BackupDirectory = backup, QueueCapacity = 1,
            RescanInterval = TimeSpan.FromHours(1)
        });
        engine.CaptureCommitted += (_, r) =>
        {
            entered.TrySetResult();
            release.Wait(TimeSpan.FromSeconds(10));
        };
        using var stop = new CancellationTokenSource();
        Task run = engine.RunAsync(stop.Token);
        try
        {
            await engine.Ready.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(monitor, "first.bin"), "one", Ct);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            for (int i = 0; i < 20; i++)
                await File.WriteAllTextAsync(Path.Combine(monitor, $"drop-{i}.bin"), "data", Ct);
            await UntilAsync(() => engine.QueueDropCount > 0);
        }
        finally
        {
            release.Set();
            stop.Cancel();
            await run.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task SharingViolationIsRetriedByReconciliationWithoutBlockingOtherFiles()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        var captured = new ConcurrentQueue<CaptureRecord>();
        var engine = new GuardianEngine(new GuardianOptions
        {
            MonitorDirectory = monitor, BackupDirectory = backup,
            RescanInterval = TimeSpan.FromMilliseconds(50)
        });
        engine.CaptureCommitted += (_, r) => captured.Enqueue(r);
        using var stop = new CancellationTokenSource();
        Task run = engine.RunAsync(stop.Token);
        try
        {
            await engine.Ready.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            await using (var locked = new FileStream(Path.Combine(monitor, "locked.bin"),
                FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                await locked.WriteAsync("locked artifact"u8.ToArray(), Ct);
                await locked.FlushAsync(Ct);
                await UntilAsync(() => engine.OpenMissCount > 0);
                await File.WriteAllTextAsync(Path.Combine(monitor, "other.bin"), "other", Ct);
                await UntilAsync(() => captured.Any(r => r.Metadata.RelativePath == "other.bin"));
            }
            await UntilAsync(() => captured.Any(r => r.Metadata.RelativePath == "locked.bin"));
            Assert.Equal("locked artifact", await File.ReadAllTextAsync(
                captured.First(r => r.Metadata.RelativePath == "locked.bin").ContentPath, Ct));
        }
        finally
        {
            stop.Cancel();
            await run;
        }
    }

    [Fact]
    public async Task EmptyMarkerArtifactIsPreserved()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        var captured = new ConcurrentQueue<CaptureRecord>();
        var engine = new GuardianEngine(new GuardianOptions { MonitorDirectory = monitor, BackupDirectory = backup });
        engine.CaptureCommitted += (_, r) => captured.Enqueue(r);
        using var stop = new CancellationTokenSource();
        Task run = engine.RunAsync(stop.Token);
        try
        {
            await engine.Ready.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            File.Create(Path.Combine(monitor, "infection-marker.lock")).Dispose();
            await UntilAsync(() => captured.Any(r => r.Metadata.RelativePath == "infection-marker.lock"));
            Assert.All(captured, r => Assert.Equal(0, r.Metadata.CapturedLength));
        }
        finally
        {
            stop.Cancel();
            await run;
        }
    }

    [Fact]
    public async Task AcquisitionHandleStillReadsAfterRenameAndDeleteAndIsDisposed()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon");
        var engine = new GuardianEngine(new GuardianOptions { MonitorDirectory = monitor });
        string path = Path.Combine(monitor, "a.exe");
        await File.WriteAllTextAsync(path, "payload", Ct);
        var request = Assert.IsType<CaptureRequest>(engine.TryAcquire(path, monitor, CaptureTrigger.Watcher));
        var handle = request.Source!.SafeFileHandle;
        string renamed = path + ".renamed";
        File.Move(path, renamed);
        File.Delete(renamed);
        using var reader = new StreamReader(request.Source, leaveOpen: true);
        Assert.Equal("payload", await reader.ReadToEndAsync(Ct));
        request.Dispose();
        Assert.True(handle.IsClosed);
    }
}
