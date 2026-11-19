using System.Text;
using FileGuardian.Core;
using FileGuardian.Core.Plugins;
using FileGuardian.Protocol;

namespace FileGuardian.Tests;

public class SafetyTests
{
    [Fact]
    public void IsWithin_DoesNotMatchSiblingPrefix()
    {
        string root = Path.Combine(Path.GetTempPath(), "data");
        Assert.True(PathSafety.IsWithin(root, Path.Combine(root, "a.txt")));
        Assert.False(PathSafety.IsWithin(root, root + "-backup"));
    }

    [Theory]
    [InlineData("../evil")]
    [InlineData("sub/../../evil")]
    public void ResolveContained_RejectsTraversal(string relative)
    {
        string root = Path.Combine(Path.GetTempPath(), "plugin");
        Assert.Throws<InvalidDataException>(() => PathSafety.ResolveContained(root, relative));
    }

    [Fact]
    public void ResolveContained_RejectsAbsolute() =>
        Assert.Throws<InvalidDataException>(() =>
            PathSafety.ResolveContained(Path.GetTempPath(), Path.Combine(Path.GetTempPath(), "x")));

    [Fact]
    public void Sanitizer_EscapesBidiOverrideAndControls()
    {
        string spoof = "invoice\u202Egpj.exe\n";
        Assert.Equal("invoice\u27E6U+202E\u27E7gpj.exe\u27E6U+000A\u27E7", TextSanitizer.ForDisplay(spoof));

        // A name that only *looks* like an escape must not collide with the real thing.
        Assert.NotEqual(TextSanitizer.ForDisplay("invoice\u202Egpj.exe"),
                        TextSanitizer.ForDisplay("invoice\u27E6U+202E\u27E7gpj.exe"));
        Assert.Equal("a\\u202Eb", TextSanitizer.ForDisplay("a\\u202Eb"));
        Assert.Equal("x\u27E6U+200B\u27E7y", TextSanitizer.ForDisplay("x\u200By"));
    }

    [Fact]
    public async Task LineReader_RejectsOversizedMessage()
    {
        byte[] big = Encoding.UTF8.GetBytes(new string('a', 5000) + "\n");
        var reader = new BoundedLineReader(new MemoryStream(big), maxLineBytes: 1000);
        await Assert.ThrowsAsync<ProtocolViolationException>(
            async () => await reader.ReadLineAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LineReader_TruncatesWhenAskedAndResyncs()
    {
        byte[] data = Encoding.UTF8.GetBytes(new string('a', 5000) + "\nnext\n");
        var reader = new BoundedLineReader(new MemoryStream(data), 100, truncateOversizedLines: true);
        string? first = await reader.ReadLineAsync(TestContext.Current.CancellationToken);
        string? second = await reader.ReadLineAsync(TestContext.Current.CancellationToken);
        Assert.StartsWith(new string('a', 100), first);
        Assert.EndsWith("[truncated]", first);
        Assert.Equal("next", second);
    }

    [Fact]
    public void PanelSanitizer_ClampsAndDropsUnknownTypes()
    {
        var rows = Enumerable.Range(0, 2000).Select(i => (IReadOnlyList<string>)[$"r{i}", "x", "extra"]).ToList();
        var model = new PanelModel("t", [
            new PanelElement("script", Text: "alert(1)"),
            new PanelElement(PanelElementTypes.Table, Columns: ["a", "b"], Rows: rows)
        ]);

        PanelModel clean = PanelSanitizer.Sanitize(model);

        PanelElement table = Assert.Single(clean.Elements);
        Assert.Equal(PanelSanitizer.MaxRows, table.Rows!.Count);
        Assert.All(table.Rows, r => Assert.Equal(2, r.Count));
    }

    [Fact]
    public void TrustDigest_ChangesWhenAnyFileChanges()
    {
        using var tmp = new TempDir();
        string dir = tmp.Sub("p");
        File.WriteAllText(Path.Combine(dir, "a.dll"), "one");
        File.WriteAllText(Path.Combine(dir, "b.json"), "two");

        string before = PluginTrustStore.ComputeDirectoryDigest(dir);
        File.AppendAllText(Path.Combine(dir, "b.json"), "!");
        string after = PluginTrustStore.ComputeDirectoryDigest(dir);

        Assert.NotEqual(before, after);

        var store = new PluginTrustStore(Path.Combine(tmp.Path, "trust.json"));
        store.Trust("x.y", before);
        Assert.False(store.IsTrusted("x.y", after));
        Assert.True(new PluginTrustStore(Path.Combine(tmp.Path, "trust.json")).IsTrusted("x.y", before));
    }
}
