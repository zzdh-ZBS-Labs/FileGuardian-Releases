using System.Globalization;
using FileGuardian.Protocol;

namespace FileGuardian.Plugin.Sdk;

/// <summary>
/// Base class for plugins. Override only the hooks you declare in
/// <see cref="Describe"/>. Handlers may run concurrently; keep state thread-safe.
/// </summary>
public abstract class FileGuardianPlugin
{
    private PluginSession? _session;
    private volatile IReadOnlyDictionary<string, string> _settings = new Dictionary<string, string>();

    public abstract PluginDescription Describe();

    /// <summary>Current settings: user values merged over declared defaults.</summary>
    protected IReadOnlyDictionary<string, string> Settings => _settings;

    public virtual Task OnInitializedAsync(CancellationToken token) => Task.CompletedTask;

    public virtual Task<FilterResult> FilterAsync(FilterParams request, CancellationToken token) =>
        Task.FromResult(new FilterResult(true));

    public virtual Task<AnalyzeResult> AnalyzeAsync(AnalyzeParams request, CancellationToken token) =>
        Task.FromResult(new AnalyzeResult(Verdicts.Info));

    public virtual Task OnEventAsync(HostEvent hostEvent, CancellationToken token) => Task.CompletedTask;

    public virtual Task<PanelModel> GetPanelAsync(CancellationToken token) =>
        Task.FromResult(new PanelModel(Describe().Name, []));

    public virtual Task<PanelModel> OnPanelActionAsync(string actionId, CancellationToken token) =>
        GetPanelAsync(token);

    public virtual Task OnSettingsChangedAsync(CancellationToken token) => Task.CompletedTask;

    // ---- helpers for plugin authors ----

    protected void Log(string level, string message) => _session?.Notify(
        ProtocolConstants.Methods.Log, new LogParams(level, message));

    /// <summary>Ask the host to re-fetch this plugin's panel.</summary>
    protected void NotifyPanelChanged() => _session?.Notify(
        ProtocolConstants.Methods.PanelChanged, EmptyResult.Instance);

    protected string GetString(string key, string fallback = "") =>
        _settings.TryGetValue(key, out string? v) ? v : fallback;

    protected bool GetBool(string key, bool fallback = false) =>
        _settings.TryGetValue(key, out string? v) && bool.TryParse(v, out bool b) ? b : fallback;

    protected long GetInt(string key, long fallback = 0) =>
        _settings.TryGetValue(key, out string? v) &&
        long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out long n) ? n : fallback;

    protected double GetNumber(string key, double fallback = 0) =>
        _settings.TryGetValue(key, out string? v) &&
        double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out double d) ? d : fallback;

    internal void Attach(PluginSession session) => _session = session;

    internal void ApplySettings(Dictionary<string, string>? values)
    {
        var merged = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (SettingDefinition def in Describe().Settings ?? [])
        {
            if (def.DefaultValue is not null)
                merged[def.Key] = def.DefaultValue;
        }

        foreach (var (k, v) in values ?? [])
            merged[k] = v;

        _settings = merged;
    }
}
