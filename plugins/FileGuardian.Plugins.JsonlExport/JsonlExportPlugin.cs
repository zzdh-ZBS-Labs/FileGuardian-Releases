using System.Globalization;
using System.Text;
using System.Text.Json;
using FileGuardian.Plugin.Sdk;
using FileGuardian.Protocol;

/// <summary>
/// Notification/export hook. Writes one JSON object per line, which a SIEM
/// agent can tail (for example Wazuh &lt;localfile&gt; with log_format json).
/// </summary>
internal sealed class JsonlExportPlugin : FileGuardianPlugin
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private long _written;
    private string? _lastError;

    public override PluginDescription Describe() => new(
        ProtocolConstants.ProtocolVersion,
        Id: "zbs.jsonl-export",
        Name: "JSON-lines event export",
        Version: "1.0.0",
        Capabilities: [ProtocolConstants.Capabilities.Notify, ProtocolConstants.Capabilities.Panel],
        Settings:
        [
            new SettingDefinition("outputPath", "Output file (blank = default)", SettingTypes.String, ""),
            new SettingDefinition("maxMegabytes", "Rotate at (MB)", SettingTypes.Int, "50"),
            new SettingDefinition("includeWarnings", "Export warnings and errors", SettingTypes.Bool, "true")
        ],
        Description: "Appends capture, analysis and engine events to a .jsonl file for SIEM ingestion.");

    private string OutputPath
    {
        get
        {
            string configured = GetString("outputPath");
            if (!string.IsNullOrWhiteSpace(configured) && Path.IsPathFullyQualified(configured))
                return configured;

            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FileGuardian", "events.jsonl");
        }
    }

    public override async Task OnEventAsync(HostEvent e, CancellationToken token)
    {
        if (!GetBool("includeWarnings", true) && e.Kind is EventKinds.Warning or EventKinds.Error)
            return;

        try
        {
            string path = OutputPath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            Rotate(path);

            var record = new
            {
                source = "fileguardian",
                kind = e.Kind,
                timestamp = e.TimestampUtc,
                message = e.Message,
                captureId = e.CaptureId,
                data = e.Data
            };

            string line = JsonSerializer.Serialize(record, Json) + "\n";
            await File.AppendAllTextAsync(path, line, new UTF8Encoding(false), token);
            Interlocked.Increment(ref _written);
            _lastError = null;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            Log("warn", $"Export failed: {ex.Message}");
        }
    }

    private void Rotate(string path)
    {
        long limit = Math.Max(1, GetInt("maxMegabytes", 50)) * 1024 * 1024;
        var info = new FileInfo(path);
        if (info.Exists && info.Length >= limit)
            File.Move(path, path + ".1", overwrite: true);
    }

    public override Task<PanelModel> GetPanelAsync(CancellationToken token) =>
        Task.FromResult(new PanelModel("Export", [
            new PanelElement(PanelElementTypes.Heading, Text: "JSON-lines export"),
            new PanelElement(PanelElementTypes.KeyValue, Items: [
                new KeyValueItem("Output", OutputPath),
                new KeyValueItem("Events written", Interlocked.Read(ref _written).ToString(CultureInfo.InvariantCulture)),
                new KeyValueItem("Last error", _lastError ?? "none")
            ]),
            new PanelElement(PanelElementTypes.Text,
                Text: "Wazuh example: <localfile><log_format>json</log_format><location>(output path)</location></localfile>"),
            new PanelElement(PanelElementTypes.Button, Label: "Refresh", ActionId: "refresh")
        ]));
}
