using System.Globalization;
using FileGuardian.Plugin.Sdk;
using FileGuardian.Protocol;

/// <summary>
/// Legacy filter protocol used as post-preservation advisory policy.
/// Temporary files can be malware evidence, so recommendations never discard them.
/// </summary>
internal sealed class ExtensionFilterPlugin : FileGuardianPlugin
{
    private volatile Rules _rules = Rules.Empty;
    private long _seen;
    private long _skipped;

    public override PluginDescription Describe() => new(
        ProtocolConstants.ProtocolVersion,
        Id: "zbs.extension-filter",
        Name: "Extension & path advisory",
        Version: "2.2.0",
        Capabilities: [ProtocolConstants.Capabilities.Filter, ProtocolConstants.Capabilities.Panel],
        Settings:
        [
            new SettingDefinition("excludedExtensions", "Flag extensions (advisory, comma-separated)",
                SettingTypes.String, ".tmp,.temp,.swp,.part,.crdownload,.lock"),
            new SettingDefinition("excludedFolders", "Flag folder names (advisory, comma-separated)",
                SettingTypes.String, ".git,node_modules,__pycache__"),
            new SettingDefinition("maxMegabytes", "Flag files larger than (MB, 0 = disabled)",
                SettingTypes.Int, "0")
        ],
        Description: "Advisory rules evaluated after preservation. Never skips or deletes captured artifacts.");

    public override Task OnInitializedAsync(CancellationToken token) { Rebuild(); return Task.CompletedTask; }
    public override Task OnSettingsChangedAsync(CancellationToken token) { Rebuild(); NotifyPanelChanged(); return Task.CompletedTask; }

    public override Task<FilterResult> FilterAsync(FilterParams request, CancellationToken token)
    {
        Interlocked.Increment(ref _seen);
        Rules rules = _rules;

        string? reason =
            rules.Extensions.Contains(request.Extension) ? $"extension {request.Extension}"
            : rules.MaxBytes > 0 && request.Length > rules.MaxBytes ? "size limit"
            : request.RelativePath
                .Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries)
                .SkipLast(1)
                .FirstOrDefault(rules.Folders.Contains) is { } folder ? $"folder {folder}"
            : null;

        if (reason is null)
            return Task.FromResult(new FilterResult(true));

        Interlocked.Increment(ref _skipped);
        return Task.FromResult(new FilterResult(false, reason));
    }

    public override Task<PanelModel> GetPanelAsync(CancellationToken token)
    {
        Rules r = _rules;
        return Task.FromResult(new PanelModel("Filter", [
            new PanelElement(PanelElementTypes.Heading, Text: "Post-preservation advisory (all evidence retained)"),
            new PanelElement(PanelElementTypes.KeyValue, Items: [
                new KeyValueItem("Files checked", Interlocked.Read(ref _seen).ToString(CultureInfo.InvariantCulture)),
                new KeyValueItem("Recommendations only", Interlocked.Read(ref _skipped).ToString(CultureInfo.InvariantCulture)),
                new KeyValueItem("Extensions", string.Join(" ", r.Extensions.Order())),
                new KeyValueItem("Folders", string.Join(" ", r.Folders.Order())),
                new KeyValueItem("Max size", r.MaxBytes == 0 ? "engine limit" : $"{r.MaxBytes / (1024 * 1024)} MB")
            ]),
            new PanelElement(PanelElementTypes.Button, Label: "Reset counters", ActionId: "reset")
        ]));
    }

    public override Task<PanelModel> OnPanelActionAsync(string actionId, CancellationToken token)
    {
        if (actionId == "reset")
        {
            Interlocked.Exchange(ref _seen, 0);
            Interlocked.Exchange(ref _skipped, 0);
        }
        return GetPanelAsync(token);
    }

    private void Rebuild()
    {
        static HashSet<string> Split(string s, bool dot) => s
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => dot && !x.StartsWith('.') ? "." + x : x)
            .ToHashSet(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

        _rules = new Rules(
            Split(GetString("excludedExtensions"), dot: true),
            Split(GetString("excludedFolders"), dot: false),
            Math.Max(0, GetInt("maxMegabytes")) * 1024 * 1024);
    }

    private sealed record Rules(HashSet<string> Extensions, HashSet<string> Folders, long MaxBytes)
    {
        public static readonly Rules Empty = new([], [], 0);
    }
}
