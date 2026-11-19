using System.Security.Cryptography;
using FileGuardian.Core;

namespace FileGuardian.Tests;

public class EngineTests
{
    private sealed class Filter(Func<CaptureCandidate, bool> decide) : ICaptureFilter
    {
        public ValueTask<bool> ShouldCaptureAsync(CaptureCandidate c, CancellationToken t) => ValueTask.FromResult(decide(c));
    }

    private static async Task<(List<CaptureRecord> Captures, GuardianExitReason Reason)> RunAsync(
        string monitor, string backup, Func<Task> act, ICaptureFilter? filter = null)
    {
        var captures = new List<CaptureRecord>();
        var engine = new GuardianEngine(new GuardianOptions
        {
            MonitorDirectory = monitor,
            BackupDirectory = backup,
            RescanInterval = TimeSpan.FromMilliseconds(200)
        }, filter);

        engine.CaptureCommitted += (_, r) => { lock (captures) captures.Add(r); };

        using var stop = new CancellationTokenSource();
        Task<GuardianExitReason> run = engine.RunAsync(stop.Token);

        await engine.Ready.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await act();
        await Task.Delay(1500);

        stop.Cancel();
        GuardianExitReason reason = await run;
        return (captures, reason);
    }

    [Fact]
    public async Task CapturesFileWithMatchingHashAndMetadata()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        byte[] content = RandomNumberGenerator.GetBytes(10_000);

        var (captures, reason) = await RunAsync(monitor, backup,
            () => File.WriteAllBytesAsync(Path.Combine(monitor, "a.bin"), content));

        Assert.Equal(GuardianExitReason.Stopped, reason);

        // Live capture can legitimately record an intermediate state of a file
        // that is still being written; the final state must be present exactly once.
        string expected = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        CaptureRecord record = Assert.Single(captures, c => c.Metadata.Sha256 == expected);
        Assert.Equal(content, await File.ReadAllBytesAsync(record.ContentPath, TestContext.Current.CancellationToken));
        Assert.True(record.Metadata.ReachedInitialLength);

        // Indexed, published under its exact name, nothing left in staging.
        Assert.Contains(CaptureIndex.Read(backup).Captures, c => c.CaptureId == record.Metadata.CaptureId);
        Assert.Equal(content, await File.ReadAllBytesAsync(Path.Combine(backup, "mon", "a.bin"), TestContext.Current.CancellationToken));
        Assert.Empty(Directory.GetFileSystemEntries(CaptureLayout.StagingDirectory(backup)));
    }

    [Fact]
    public async Task IdenticalContentIsNotRecaptured_ButNewVersionIs()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        string file = Path.Combine(monitor, "doc.txt");

        var (captures, _) = await RunAsync(monitor, backup, async () =>
        {
            await File.WriteAllTextAsync(file, "v1");
            await Task.Delay(600);
            File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddMinutes(-5)); // touch without content change
            await Task.Delay(600);
            await File.WriteAllTextAsync(file, "v2");
        });

        string Hash(string text) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
        var hashes = captures.Select(c => c.Metadata.Sha256).ToList();

        Assert.Equal(hashes.Count, hashes.Distinct().Count()); // never the same bytes twice in a row
        Assert.Contains(Hash("v1"), hashes);
        Assert.Contains(Hash("v2"), hashes);
        // Empty intermediates/marker files are evidence too.
    }

    [Fact]
    public async Task LegacyFilterCannotDiscardEvidence()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");

        var (captures, _) = await RunAsync(monitor, backup, async () =>
        {
            await File.WriteAllTextAsync(Path.Combine(monitor, "keep.txt"), "k");
            await File.WriteAllTextAsync(Path.Combine(monitor, "skip.tmp"), "s");
        }, new Filter(c => !c.RelativePath.EndsWith(".tmp")));

        Assert.Contains(captures, c => c.Metadata.RelativePath == "keep.txt");
        Assert.Contains(captures, c => c.Metadata.RelativePath == "skip.tmp");
    }

    [Fact]
    public async Task ThrowingFilterFailsOpen()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");

        var (captures, _) = await RunAsync(monitor, backup,
            () => File.WriteAllTextAsync(Path.Combine(monitor, "a.txt"), "x"),
            new Filter(_ => throw new InvalidOperationException("boom")));

        Assert.Contains(captures, c => c.Metadata.CapturedLength == 1);
    }

    [Fact]
    public async Task OverlappingDirectoriesAreRejected()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon");
        var engine = new GuardianEngine(new GuardianOptions
        {
            MonitorDirectory = monitor,
            BackupDirectory = Path.Combine(monitor, "inside")
        });

        Assert.Equal(GuardianExitReason.Failed, await engine.RunAsync(TestContext.Current.CancellationToken));
    }
}
