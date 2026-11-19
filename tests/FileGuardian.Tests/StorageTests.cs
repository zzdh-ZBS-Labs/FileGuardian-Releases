using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using FileGuardian.Core;

namespace FileGuardian.Tests;

public class StorageTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
    private static string Sha(string s) => Sha(Encoding.UTF8.GetBytes(s));

    private static async Task<List<CaptureRecord>> RunAsync(string monitor, string backup, Func<Task> act, int settleMs = 1500,
        bool captureExisting = false)
    {
        var captures = new List<CaptureRecord>();
        var engine = new GuardianEngine(new GuardianOptions
        {
            MonitorDirectory = monitor,
            BackupDirectory = backup,
            CaptureExistingFiles = captureExisting,
            RescanInterval = TimeSpan.FromMilliseconds(200)
        });
        engine.CaptureCommitted += (_, r) => { lock (captures) captures.Add(r); };

        using var stop = new CancellationTokenSource();
        Task<GuardianExitReason> run = engine.RunAsync(stop.Token);
        await engine.Ready.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await act();
        await Task.Delay(settleMs);
        stop.Cancel();
        Assert.Equal(GuardianExitReason.Stopped, await run);
        return captures;
    }

    [Fact]
    public async Task MirrorsSourceTreeWithExactNames()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("Downloads"), backup = tmp.Sub("bak");
        Directory.CreateDirectory(Path.Combine(monitor, "tools", "x64"));

        await RunAsync(monitor, backup, async () =>
        {
            await File.WriteAllTextAsync(Path.Combine(monitor, "invoice.pdf"), "pdf", Ct);
            await File.WriteAllTextAsync(Path.Combine(monitor, "tools", "x64", "setup.exe"), "MZ", Ct);
        });

        Assert.Equal("pdf", await File.ReadAllTextAsync(Path.Combine(backup, "Downloads", "invoice.pdf"), Ct));
        Assert.Equal("MZ", await File.ReadAllTextAsync(Path.Combine(backup, "Downloads", "tools", "x64", "setup.exe"), Ct));

        // Only the mirrored folder and the internal folder at the top level.
        Assert.Equal(["Downloads", ".fileguardian"],
            Directory.GetFileSystemEntries(backup).Select(Path.GetFileName).OrderByDescending(n => n));

        // Version: versions/<root>/<relative path>/<UTC time> [sha8]/<exact name>
        string versionDir = Assert.Single(Directory.GetDirectories(
            Path.Combine(CaptureLayout.VersionsDirectory(backup), "Downloads", "invoice.pdf")),
            d => Path.GetFileName(d).EndsWith($"[{Sha("pdf")[..8]}]", StringComparison.Ordinal));
        Assert.Matches(new Regex(@"^\d{4}-\d{2}-\d{2} \d{2}\.\d{2}\.\d{2}Z \[" + Sha("pdf")[..8] + @"\]$"),
            Path.GetFileName(versionDir));
        Assert.Equal("pdf", await File.ReadAllTextAsync(Path.Combine(versionDir, "invoice.pdf"), Ct));
    }

    [Fact]
    public async Task NewVersionReplacesLatestCopyAndKeepsOlder()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        string file = Path.Combine(monitor, "notes.txt");

        await RunAsync(monitor, backup, async () =>
        {
            await File.WriteAllTextAsync(file, "version one", Ct);
            await Task.Delay(700, Ct);
            await File.WriteAllTextAsync(file, "version two!", Ct);
        });

        Assert.Equal("version two!", await File.ReadAllTextAsync(Path.Combine(backup, "mon", "notes.txt"), Ct));

        var listing = CaptureStore.LoadRecent(backup, 100);
        var v1 = Assert.Single(listing, l => l.Record.Metadata.Sha256 == Sha("version one"));
        var v2 = Assert.Single(listing, l => l.Record.Metadata.Sha256 == Sha("version two!"));
        Assert.False(v1.IsLatest);
        Assert.True(v2.IsLatest);
        Assert.Equal("version one", await File.ReadAllTextAsync(v1.Record.ContentPath, Ct));
        Assert.Equal("mon/notes.txt", v1.Record.DisplayPath);
    }

    [Fact]
    public async Task RestartDoesNotRecaptureUnchangedFiles()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");
        await File.WriteAllTextAsync(Path.Combine(monitor, "a.txt"), "alpha", Ct);
        await File.WriteAllTextAsync(Path.Combine(monitor, "b.txt"), "bravo", Ct);

        var first = await RunAsync(monitor, backup, () => Task.CompletedTask);
        Assert.Empty(first);

        var second = await RunAsync(monitor, backup, () => Task.CompletedTask);
        Assert.Empty(second);

        // A new session establishes its own metadata-only baseline, including
        // changes made while stopped. Collection of old content is explicit.
        await File.WriteAllTextAsync(Path.Combine(monitor, "a.txt"), "alpha 2", Ct);
        var third = await RunAsync(monitor, backup, () => Task.CompletedTask);
        Assert.Empty(third);
        var explicitCollection = await RunAsync(monitor, backup, () => Task.CompletedTask, captureExisting: true);
        Assert.Contains(explicitCollection, c => c.Metadata.Sha256 == Sha("alpha 2"));
    }

    [Fact]
    public async Task SecondWriterProcessIsRejected()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");

        // Stands in for another process: holds the lock outside the shared cache.
        using CaptureIndexWriter other = CaptureIndexWriter.OpenExclusive(backup);
        other.AddRefForTest();

        var engine = new GuardianEngine(new GuardianOptions { MonitorDirectory = monitor, BackupDirectory = backup });
        string? error = null;
        engine.LogEmitted += (_, e) => { if (e.Level == GuardianLogLevel.Error) error = e.Message; };

        Assert.Equal(GuardianExitReason.Failed, await engine.RunAsync(Ct));
        Assert.Contains("in use by another FileGuardian process", error);
    }

    [Fact]
    public async Task RecoveryFinishesInterruptedPublish()
    {
        using var tmp = new TempDir();
        string backup = tmp.Sub("bak");
        string id = $"{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfffffffZ}_{Guid.NewGuid():N}";
        string sha = Sha("data");

        using (CaptureIndexWriter w = CaptureIndexWriter.Acquire(backup))
        {
            var meta = new CaptureMetadata
            {
                CaptureId = id, OriginalPath = Path.Combine(tmp.Path, "mon", "f.txt"), RelativePath = "f.txt",
                Sha256 = sha, CapturedLength = 4, InitialLength = 4, ReachedInitialLength = true,
                StartedUtc = DateTimeOffset.UtcNow, RootName = "mon", ContentFile = "f.txt",
                StoredPath = $".fileguardian/versions/mon/f.txt/X [{sha[..8]}]/f.txt", MirrorPath = "mon/f.txt"
            };
            await w.AppendAsync(new IndexEntry { Type = IndexEntry.CaptureType, Capture = meta }, Ct);

            // Crash after the index entry, before the rename.
            string staged = Path.Combine(CaptureLayout.StagingDirectory(backup), id);
            Directory.CreateDirectory(staged);
            await File.WriteAllTextAsync(Path.Combine(staged, "f.txt"), "data", Ct);

            // An abandoned staging folder with no index entry is removed.
            Directory.CreateDirectory(Path.Combine(CaptureLayout.StagingDirectory(backup), "orphan"));

            await CaptureStore.RecoverAsync(w, null, Ct);
        }

        var record = Assert.Single(CaptureStore.LoadRecent(backup, 10)).Record;
        Assert.Equal("data", await File.ReadAllTextAsync(record.ContentPath, Ct));
        Assert.Empty(Directory.GetFileSystemEntries(CaptureLayout.StagingDirectory(backup)));
    }

    [Fact]
    public async Task DamagedIndexTailIsToleratedAndNotGluedToNextEntry()
    {
        using var tmp = new TempDir();
        string monitor = tmp.Sub("mon"), backup = tmp.Sub("bak");

        await RunAsync(monitor, backup, () => File.WriteAllTextAsync(Path.Combine(monitor, "one.txt"), "1", Ct));
        await File.AppendAllTextAsync(CaptureLayout.IndexPath(backup), "{\"type\":\"capture\",\"capt", Ct); // torn write
        await RunAsync(monitor, backup, () => File.WriteAllTextAsync(Path.Combine(monitor, "two.txt"), "2", Ct));

        var names = CaptureIndex.Read(backup).Captures.Select(c => c.RelativePath).ToList();
        Assert.Contains("one.txt", names);
        Assert.Contains("two.txt", names);
    }

    [Fact]
    public void RootNamesAreUniqueAndAvoidTheInternalFolder()
    {
        using var tmp = new TempDir();
        string backup = tmp.Sub("bak");
        using CaptureIndexWriter w = CaptureIndexWriter.Acquire(backup);

        string a = CaptureLayout.GetOrAddRootName(backup, Path.Combine(tmp.Path, "a", "Downloads"));
        string b = CaptureLayout.GetOrAddRootName(backup, Path.Combine(tmp.Path, "b", "Downloads"));
        string again = CaptureLayout.GetOrAddRootName(backup, Path.Combine(tmp.Path, "a", "Downloads"));
        string hidden = CaptureLayout.GetOrAddRootName(backup, Path.Combine(tmp.Path, ".fileguardian"));

        Assert.Equal("Downloads", a);
        Assert.Equal("Downloads (2)", b);
        Assert.Equal("Downloads", again);
        Assert.Equal("_fileguardian", hidden);
    }

    [Theory]
    [InlineData("../outside.txt")]
    [InlineData("mon/../../outside.txt")]
    [InlineData("/etc/passwd")]
    [InlineData("")]
    public void IndexPathsCannotEscapeTheBackupFolder(string stored)
    {
        using var tmp = new TempDir();
        Assert.ThrowsAny<Exception>(() => CaptureLayout.Resolve(tmp.Path, stored));
    }

    [Fact]
    public async Task ConvertsOldFormatCaptures()
    {
        using var tmp = new TempDir();
        string backup = tmp.Sub("bak");
        string monitor = Path.Combine(tmp.Path, "Desktop");

        async Task<string> Legacy(DateTimeOffset when, string rel, string content, bool withAnalysis)
        {
            string id = $"{when:yyyyMMddTHHmmssfffffffZ}_{Guid.NewGuid():N}";
            string dir = Path.Combine(backup, id);
            Directory.CreateDirectory(dir);
            await File.WriteAllTextAsync(Path.Combine(dir, "content.bin"), content, Ct);
            await File.WriteAllTextAsync(Path.Combine(dir, "metadata.json"), JsonSerializer.Serialize(new
            {
                SchemaVersion = 2, CaptureId = id, OriginalPath = Path.Combine(monitor, rel), RelativePath = rel,
                StartedUtc = when, CompletedUtc = when, InitialLength = content.Length, CapturedLength = content.Length,
                ReachedInitialLength = true, Sha256 = Sha(content), ContentFile = "content.bin"
            }), Ct);
            if (withAnalysis)
            {
                Directory.CreateDirectory(Path.Combine(dir, "analysis"));
                await File.WriteAllTextAsync(Path.Combine(dir, "analysis", "entropy.json"), JsonSerializer.Serialize(
                    new StoredAnalysis("entropy", "Entropy", "suspicious", "packed", ["upx"],
                        new Dictionary<string, string> { ["entropy"] = "7.9" }, when)), Ct);
            }
            return id;
        }

        var t0 = DateTimeOffset.UtcNow.AddHours(-2);
        await Legacy(t0, Path.Combine("tools", "app.exe"), "old build", true);
        await Legacy(t0.AddMinutes(5), Path.Combine("tools", "app.exe"), "new build", false);
        Directory.CreateDirectory(Path.Combine(backup, ".partial-leftover"));

        Assert.Equal(2, CaptureStore.CountLegacy(backup));
        var result = await CaptureStore.MigrateLegacyAsync(backup, null, Ct);

        Assert.Equal(2, result.Converted);
        Assert.Equal(0, result.Failed);
        Assert.Equal(0, CaptureStore.CountLegacy(backup));
        Assert.Equal(["Desktop", ".fileguardian"],
            Directory.GetFileSystemEntries(backup).Select(Path.GetFileName).OrderByDescending(n => n));

        Assert.Equal("new build", await File.ReadAllTextAsync(Path.Combine(backup, "Desktop", "tools", "app.exe"), Ct));

        var listing = CaptureStore.LoadRecent(backup, 10);
        var old = Assert.Single(listing, l => l.Record.Metadata.Sha256 == Sha("old build"));
        Assert.Equal("old build", await File.ReadAllTextAsync(old.Record.ContentPath, Ct));
        Assert.Equal("suspicious", Assert.Single(old.Analyses).Verdict);
        Assert.True(old.Record.Metadata.Migrated);

        // Re-running is harmless.
        Assert.Equal(0, (await CaptureStore.MigrateLegacyAsync(backup, null, Ct)).Converted);
        Assert.Equal(2, CaptureStore.LoadRecent(backup, 10).Count);
    }
}
