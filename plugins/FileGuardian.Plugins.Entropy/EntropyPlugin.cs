using System.Globalization;
using FileGuardian.Plugin.Sdk;
using FileGuardian.Protocol;

/// <summary>
/// Post-capture triage: Shannon entropy plus magic-byte file typing.
/// High entropy in an executable is a common packing/encryption signal.
/// This is a triage hint, not a malware verdict, so it never reports "clean".
/// </summary>
internal sealed class EntropyPlugin : FileGuardianPlugin
{
    private const int RecentLimit = 50;

    private readonly object _gate = new();
    private readonly LinkedList<string[]> _recent = new();
    private long _analyzed;
    private long _flagged;

    public override PluginDescription Describe() => new(
        ProtocolConstants.ProtocolVersion,
        Id: "zbs.entropy",
        Name: "Entropy & file-type triage",
        Version: "1.0.0",
        Capabilities: [ProtocolConstants.Capabilities.Analyze, ProtocolConstants.Capabilities.Panel],
        Settings:
        [
            new SettingDefinition("highEntropyThreshold", "High-entropy threshold (bits/byte)",
                SettingTypes.Number, "7.2", "0-8. Values near 8 suggest compression or encryption.")
        ],
        Description: "Flags high-entropy executables (possible packing or encryption).");

    public override async Task<AnalyzeResult> AnalyzeAsync(AnalyzeParams request, CancellationToken token)
    {
        double threshold = Math.Clamp(GetNumber("highEntropyThreshold", 7.2), 0, 8);

        long[] counts = new long[256];
        byte[] header = new byte[16];
        int headerLength = 0;
        long total = 0;

        await using (var stream = new FileStream(request.ContentPath, FileMode.Open, FileAccess.Read,
                         FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            byte[] buffer = new byte[81920];
            int read;
            while ((read = await stream.ReadAsync(buffer, token)) > 0)
            {
                if (headerLength < header.Length)
                {
                    int take = Math.Min(header.Length - headerLength, read);
                    Array.Copy(buffer, 0, header, headerLength, take);
                    headerLength += take;
                }

                for (int i = 0; i < read; i++)
                    counts[buffer[i]]++;

                total += read;
            }
        }

        double entropy = 0;
        if (total > 0)
        {
            foreach (long c in counts)
            {
                if (c == 0) continue;
                double p = (double)c / total;
                entropy -= p * Math.Log2(p);
            }
        }

        string type = DetectType(header.AsSpan(0, headerLength));
        bool executable = type is "PE" or "ELF" or "Mach-O";
        bool high = total >= 256 && entropy >= threshold;

        string verdict = high && executable ? Verdicts.Suspicious : Verdicts.Info;
        string summary = high && executable
            ? $"High-entropy {type} ({entropy:0.00}); possibly packed or encrypted"
            : high ? $"High entropy {type} ({entropy:0.00}); likely compressed or encrypted data"
            : $"{type}, entropy {entropy:0.00}";

        var tags = new List<string> { type.ToLowerInvariant() };
        if (high) tags.Add("high-entropy");

        lock (_gate)
        {
            _analyzed++;
            if (verdict == Verdicts.Suspicious) _flagged++;

            _recent.AddFirst([
                DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture),
                request.RelativePath,
                type,
                entropy.ToString("0.00", CultureInfo.InvariantCulture),
                verdict
            ]);
            while (_recent.Count > RecentLimit) _recent.RemoveLast();
        }

        NotifyPanelChanged();

        return new AnalyzeResult(verdict, summary, tags, new Dictionary<string, string>
        {
            ["entropy"] = entropy.ToString("0.0000", CultureInfo.InvariantCulture),
            ["fileType"] = type,
            ["bytes"] = total.ToString(CultureInfo.InvariantCulture)
        });
    }

    public override Task<PanelModel> GetPanelAsync(CancellationToken token)
    {
        lock (_gate)
        {
            return Task.FromResult(new PanelModel("Entropy", [
                new PanelElement(PanelElementTypes.Heading, Text: "Entropy & file-type triage"),
                new PanelElement(PanelElementTypes.Text,
                    Text: "Executables at or above the threshold are flagged as suspicious. This is a hint, not a verdict."),
                new PanelElement(PanelElementTypes.KeyValue, Items: [
                    new KeyValueItem("Analyzed this session", _analyzed.ToString(CultureInfo.InvariantCulture)),
                    new KeyValueItem("Flagged", _flagged.ToString(CultureInfo.InvariantCulture)),
                    new KeyValueItem("Threshold", GetString("highEntropyThreshold", "7.2"))
                ]),
                new PanelElement(PanelElementTypes.Table, Label: "Recent",
                    Columns: ["Time", "Path", "Type", "Entropy", "Verdict"],
                    Rows: _recent.Select(r => (IReadOnlyList<string>)r).ToList()),
                new PanelElement(PanelElementTypes.Button, Label: "Clear history", ActionId: "clear")
            ]));
        }
    }

    public override Task<PanelModel> OnPanelActionAsync(string actionId, CancellationToken token)
    {
        if (actionId == "clear")
        {
            lock (_gate)
            {
                _recent.Clear();
                _analyzed = _flagged = 0;
            }
        }

        return GetPanelAsync(token);
    }

    private static string DetectType(ReadOnlySpan<byte> h)
    {
        if (h.StartsWith("MZ"u8)) return "PE";
        if (h.StartsWith((byte[])[0x7F, (byte)'E', (byte)'L', (byte)'F'])) return "ELF";
        if (h.StartsWith((byte[])[0xFE, 0xED, 0xFA, 0xCE]) || h.StartsWith((byte[])[0xFE, 0xED, 0xFA, 0xCF]) ||
            h.StartsWith((byte[])[0xCE, 0xFA, 0xED, 0xFE]) || h.StartsWith((byte[])[0xCF, 0xFA, 0xED, 0xFE]) ||
            h.StartsWith((byte[])[0xCA, 0xFE, 0xBA, 0xBE])) return "Mach-O";
        if (h.StartsWith("%PDF"u8)) return "PDF";
        if (h.StartsWith((byte[])[0x50, 0x4B, 0x03, 0x04])) return "ZIP";
        if (h.StartsWith((byte[])[0xD0, 0xCF, 0x11, 0xE0])) return "OLE";
        if (h.StartsWith((byte[])[0x1F, 0x8B])) return "GZIP";
        if (h.StartsWith((byte[])[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return "7Z";
        if (h.StartsWith("Rar!"u8)) return "RAR";
        if (h.StartsWith("#!"u8)) return "Script";
        return h.Length == 0 ? "Empty" : "Data";
    }
}
