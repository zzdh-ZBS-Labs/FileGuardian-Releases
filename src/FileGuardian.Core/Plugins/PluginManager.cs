using System.Globalization;
using System.Threading.Channels;
using FileGuardian.Protocol;

namespace FileGuardian.Core.Plugins;

public sealed record AnalysisCompletedEventArgs(CaptureRecord Capture, StoredAnalysis Analysis);

public sealed class PluginHostOptions
{
    public TimeSpan FilterTimeout { get; init; } = TimeSpan.FromMilliseconds(500);
    public TimeSpan AnalysisTimeout { get; init; } = TimeSpan.FromMinutes(5);
    public int AnalysisQueueCapacity { get; init; } = 1024;
    public int MaxRestarts { get; init; } = 3;
    public TimeSpan RestartWindow { get; init; } = TimeSpan.FromMinutes(5);
}

/// <summary>
/// Owns all plugin processes and adapts them to the engine:
///  - pre-capture filters  -> <see cref="ICaptureFilter"/> (fail-open)
///  - post-capture analysis -> background queue; never blocks capture
///  - notifications        -> fire-and-forget fan-out, dropped if a plugin lags
///  - panels               -> exposed per plugin for the GUI
/// </summary>
public sealed class PluginManager : ICaptureFilter, IAsyncDisposable
{
    private readonly string _pluginsDirectory;
    private readonly PluginTrustStore _trust;
    private readonly AppSettings _settings;
    private readonly string _settingsPath;
    private readonly PluginHostOptions _options;
    private readonly IReadOnlyList<PluginManifest> _builtIns;
    private readonly List<PluginInstance> _plugins = [];
    private readonly object _gate = new();
    private readonly Channel<CaptureRecord> _analysisQueue;
    private readonly CancellationTokenSource _lifetime = new();
    private Task? _analysisWorker;
    private GuardianEngine? _engine;

    public PluginManager(
        string pluginsDirectory,
        PluginTrustStore trust,
        AppSettings settings,
        string settingsPath,
        PluginHostOptions? options = null,
        IReadOnlyList<PluginManifest>? builtIns = null)
    {
        _builtIns = builtIns ?? [];
        _pluginsDirectory = pluginsDirectory;
        _trust = trust;
        _settings = settings;
        _settingsPath = settingsPath;
        _options = options ?? new PluginHostOptions();
        _analysisQueue = Channel.CreateBounded<CaptureRecord>(new BoundedChannelOptions(_options.AnalysisQueueCapacity)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.DropWrite
        });
    }

    public event EventHandler<LogEntry>? LogEmitted;
    public event EventHandler? PluginsChanged;
    public event EventHandler<PluginInstance>? PluginStateChanged;
    public event EventHandler<PluginInstance>? PanelChanged;
    public event EventHandler<AnalysisCompletedEventArgs>? AnalysisCompleted;

    public string PluginsDirectory => _pluginsDirectory;

    public IReadOnlyList<PluginInstance> Plugins
    {
        get { lock (_gate) return _plugins.ToList(); }
    }

    // ------------------------------------------------------------------ lifecycle

    public async Task LoadAsync(CancellationToken token = default)
    {
        await StopAllAsync();

        Directory.CreateDirectory(_pluginsDirectory);
        var manifests = new List<PluginManifest>(_builtIns);
        foreach (PluginManifest external in PluginDiscovery.Discover(_pluginsDirectory, w => Log(GuardianLogLevel.Warn, w)))
        {
            if (manifests.Any(m => m.Id == external.Id))
                Log(GuardianLogLevel.Warn, $"External plugin '{external.Id}' ignored: a built-in plugin has the same id.");
            else
                manifests.Add(external);
        }

        lock (_gate)
        {
            _plugins.Clear();
            foreach (PluginManifest m in manifests)
            {
                var instance = new PluginInstance(m, e => Raise(LogEmitted, e));
                instance.StateChanged += p => PluginStateChanged?.Invoke(this, p);
                instance.PanelChanged += p => PanelChanged?.Invoke(this, p);
                instance.Faulted += OnPluginFaulted;
                _plugins.Add(instance);
            }
        }

        _analysisWorker ??= Task.Run(() => AnalysisLoopAsync(_lifetime.Token));
        PluginsChanged?.Invoke(this, EventArgs.Empty);

        foreach (PluginInstance p in Plugins)
            await TryStartAsync(p, token);
    }

    /// <summary>Verifies the folder digest against the trust pin, then starts.</summary>
    public async Task<bool> TryStartAsync(PluginInstance plugin, CancellationToken token = default)
    {
        if (plugin.State is PluginState.Running or PluginState.Starting)
            return true;

        if (plugin.Manifest.IsBuiltIn)
        {
            plugin.CurrentDigest = "built-in (part of the FileGuardian executable)";
            return await StartIfEnabledAsync(plugin, token);
        }

        string digest;
        try
        {
            // Computed immediately before launch to keep the
            // verify-then-execute window small.
            digest = PluginTrustStore.ComputeDirectoryDigest(plugin.Manifest.Directory);
            plugin.CurrentDigest = digest;
        }
        catch (Exception ex)
        {
            plugin.SetState(PluginState.Faulted, $"Could not verify plugin files: {ex.Message}");
            return false;
        }

        if (!_trust.IsTrusted(plugin.Id, digest))
        {
            string? pinned = _trust.GetPinnedDigest(plugin.Id);
            string why = pinned is null
                ? "Not yet approved."
                : "Plugin files changed since approval. Review and approve again.";
            plugin.SetState(PluginState.Untrusted, why);
            Log(pinned is null ? GuardianLogLevel.Info : GuardianLogLevel.Warn,
                $"Plugin '{plugin.Id}' not started: {why}");
            return false;
        }

        return await StartIfEnabledAsync(plugin, token);
    }

    private async Task<bool> StartIfEnabledAsync(PluginInstance plugin, CancellationToken token)
    {
        if (IsDisabled(plugin.Id))
        {
            plugin.SetState(PluginState.Disabled);
            return false;
        }

        try
        {
            await plugin.StartAsync(GetSettings(plugin.Id), token);
            return true;
        }
        catch (Exception ex)
        {
            Log(GuardianLogLevel.Error, $"Plugin '{plugin.Id}' failed to start: {ex.Message}");
            return false;
        }
    }

    public async Task TrustAsync(PluginInstance plugin)
    {
        if (plugin.Manifest.IsBuiltIn)
            throw new InvalidOperationException("Built-in plugins do not need approval.");

        string digest = PluginTrustStore.ComputeDirectoryDigest(plugin.Manifest.Directory);
        _trust.Trust(plugin.Id, digest);
        SetDisabled(plugin.Id, false);
        Log(GuardianLogLevel.Info, $"Approved plugin '{plugin.Id}' with digest {digest}.");
        plugin.RecentFailures = 0;
        await TryStartAsync(plugin);
    }

    public async Task RevokeAsync(PluginInstance plugin)
    {
        if (plugin.Manifest.IsBuiltIn)
            throw new InvalidOperationException("Built-in plugins cannot be revoked; disable them instead.");

        await plugin.StopAsync();
        _trust.Revoke(plugin.Id);
        plugin.SetState(PluginState.Untrusted, "Approval revoked.");
    }

    public async Task SetEnabledAsync(PluginInstance plugin, bool enabled)
    {
        SetDisabled(plugin.Id, !enabled);

        if (enabled)
        {
            plugin.RecentFailures = 0;
            await TryStartAsync(plugin);
        }
        else
        {
            await plugin.StopAsync();
            plugin.SetState(PluginState.Disabled);
        }
    }

    public async Task RestartAsync(PluginInstance plugin)
    {
        await plugin.StopAsync();
        plugin.RecentFailures = 0;
        await TryStartAsync(plugin);
    }

    public Dictionary<string, string> GetSettings(string pluginId)
    {
        lock (_gate)
            return _settings.PluginSettings.TryGetValue(pluginId, out var s)
                ? new Dictionary<string, string>(s)
                : [];
    }

    public async Task UpdateSettingsAsync(PluginInstance plugin, Dictionary<string, string> values)
    {
        Dictionary<string, string> clean = ValidateSettings(plugin, values);

        lock (_gate)
        {
            _settings.PluginSettings[plugin.Id] = clean;
            _settings.Save(_settingsPath);
        }

        if (plugin.State == PluginState.Running)
            await plugin.UpdateSettingsAsync(clean, CancellationToken.None);
    }

    // ------------------------------------------------------------------ engine wiring

    public void AttachEngine(GuardianEngine engine)
    {
        _engine = engine;
        engine.CaptureCommitted += OnCaptureCommitted;
        engine.LogEmitted += OnEngineLog;
        Broadcast(new HostEvent(EventKinds.EngineStarted, DateTimeOffset.UtcNow));
    }

    public void DetachEngine(GuardianEngine engine, GuardianExitReason reason)
    {
        engine.CaptureCommitted -= OnCaptureCommitted;
        engine.LogEmitted -= OnEngineLog;
        _engine = null;
        Broadcast(new HostEvent(EventKinds.EngineStopped, DateTimeOffset.UtcNow, reason.ToString()));
    }

    public async ValueTask<bool> ShouldCaptureAsync(CaptureCandidate candidate, CancellationToken token)
    {
        var filters = Plugins.Where(p => p.Has(ProtocolConstants.Capabilities.Filter)).ToList();
        if (filters.Count == 0)
            return true;

        var request = new FilterParams(candidate.RelativePath, Path.GetExtension(candidate.RelativePath), candidate.Length);

        var tasks = filters.Select(async p =>
        {
            try
            {
                FilterResult r = await p.FilterAsync(request, _options.FilterTimeout, token);
                return (p, r.Capture, r.Reason);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Fail open per plugin.
                Log(GuardianLogLevel.Warn, $"Advisory filter '{p.Id}' failed; artifact already preserved: {ex.Message}");
                return (p, true, (string?)null);
            }
        });

        foreach (var (plugin, capture, reason) in await Task.WhenAll(tasks))
        {
            if (!capture)
            {
                Log(GuardianLogLevel.Debug,
                    $"'{plugin.Id}' recommends exclusion (artifact retained): {candidate.RelativePath}: {TextSanitizer.ForDisplay(reason, 200)}");
                return false;
            }
        }

        return true;
    }

    /// <summary>Queues (or re-queues) analysis of an existing capture.</summary>
    public bool QueueAnalysis(CaptureRecord record)
    {
        if (_analysisQueue.Writer.TryWrite(record))
            return true;

        Log(GuardianLogLevel.Warn, $"Analysis queue full; skipped analysis of {record.Metadata.CaptureId}.");
        return false;
    }

    public void Broadcast(HostEvent hostEvent)
    {
        foreach (PluginInstance p in Plugins.Where(p => p.Has(ProtocolConstants.Capabilities.Notify)))
        {
            if (!p.TryNotify(hostEvent))
                Log(GuardianLogLevel.Debug, $"Notification to '{p.Id}' dropped (plugin is backed up).");
        }
    }

    private void OnCaptureCommitted(object? sender, CaptureRecord record)
    {
        CaptureMetadata m = record.Metadata;
        Broadcast(new HostEvent(EventKinds.CaptureCommitted, DateTimeOffset.UtcNow, null, m.CaptureId,
            new Dictionary<string, string>
            {
                ["originalPath"] = m.OriginalPath,
                ["relativePath"] = m.RelativePath,
                ["sha256"] = m.Sha256,
                ["bytes"] = m.CapturedLength.ToString(CultureInfo.InvariantCulture),
                ["complete"] = m.ReachedInitialLength ? "true" : "false"
            }));

        if (Plugins.Any(p => p.Has(ProtocolConstants.Capabilities.Analyze)))
            QueueAnalysis(record);
    }

    private void OnEngineLog(object? sender, LogEntry entry)
    {
        string? kind = entry.Level switch
        {
            GuardianLogLevel.Warn => EventKinds.Warning,
            GuardianLogLevel.Error => EventKinds.Error,
            _ => null
        };

        if (kind is not null)
            Broadcast(new HostEvent(kind, entry.TimestampUtc, entry.Message));
    }

    private async Task AnalysisLoopAsync(CancellationToken token)
    {
        try
        {
            await foreach (CaptureRecord record in _analysisQueue.Reader.ReadAllAsync(token))
            {
                var analyzers = Plugins.Where(p => p.Has(ProtocolConstants.Capabilities.Analyze)).ToList();
                await Task.WhenAll(analyzers.Select(p => AnalyzeOneAsync(p, record, token)));
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
    }

    private async Task AnalyzeOneAsync(PluginInstance plugin, CaptureRecord record, CancellationToken token)
    {
        CaptureMetadata m = record.Metadata;

        try
        {
            AnalyzeResult result = await plugin.AnalyzeAsync(
                new AnalyzeParams(m.CaptureId, record.ContentPath, m.RelativePath, m.CapturedLength, m.Sha256),
                _options.AnalysisTimeout, token);

            StoredAnalysis stored = Normalize(plugin, result);
            await CaptureStore.WriteAnalysisAsync(record, stored, token);

            Raise(AnalysisCompleted, new AnalysisCompletedEventArgs(record, stored));

            Broadcast(new HostEvent(EventKinds.AnalysisCompleted, DateTimeOffset.UtcNow, stored.Summary, m.CaptureId,
                new Dictionary<string, string>
                {
                    ["pluginId"] = plugin.Id,
                    ["verdict"] = stored.Verdict,
                    ["sha256"] = m.Sha256,
                    ["relativePath"] = m.RelativePath
                }));

            GuardianLogLevel level = Verdicts.Severity(stored.Verdict) >= 2 ? GuardianLogLevel.Warn : GuardianLogLevel.Info;
            Log(level, $"{plugin.DisplayName}: {m.RelativePath} -> {stored.Verdict}" +
                       (stored.Summary is null ? "" : $" ({stored.Summary})"));
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Log(GuardianLogLevel.Warn, $"Analysis by '{plugin.Id}' failed for {m.CaptureId}: {ex.Message}");
        }
    }

    // ------------------------------------------------------------------ restart policy

    private async void OnPluginFaulted(PluginInstance plugin)
    {
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (now - plugin.FailureWindowStart > _options.RestartWindow)
            {
                plugin.FailureWindowStart = now;
                plugin.RecentFailures = 0;
            }

            plugin.RecentFailures++;

            if (plugin.RecentFailures > _options.MaxRestarts || _lifetime.IsCancellationRequested)
            {
                Log(GuardianLogLevel.Error,
                    $"Plugin '{plugin.Id}' failed {plugin.RecentFailures} times; leaving it stopped. Use Restart to try again.");
                return;
            }

            TimeSpan delay = TimeSpan.FromSeconds(Math.Pow(3, plugin.RecentFailures - 1));
            Log(GuardianLogLevel.Warn, $"Restarting plugin '{plugin.Id}' in {delay.TotalSeconds:0}s.");
            await Task.Delay(delay, _lifetime.Token);
            await TryStartAsync(plugin, _lifetime.Token);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Log(GuardianLogLevel.Error, $"Restart of '{plugin.Id}' failed: {ex.Message}");
        }
    }

    // ------------------------------------------------------------------ helpers

    private static StoredAnalysis Normalize(PluginInstance plugin, AnalyzeResult r)
    {
        string verdict = Verdicts.All.Contains(r.Verdict ?? "") ? r.Verdict! : Verdicts.Info;

        var tags = (r.Tags ?? [])
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Take(32)
            .Select(t => TextSanitizer.ForDisplay(t, 64))
            .ToList();

        var fields = (r.Fields ?? [])
            .Take(64)
            .ToDictionary(
                kv => TextSanitizer.ForDisplay(kv.Key, 64),
                kv => TextSanitizer.ForDisplay(kv.Value, 1024));

        return new StoredAnalysis(
            plugin.Id,
            plugin.DisplayName,
            verdict,
            r.Summary is null ? null : TextSanitizer.ForDisplay(r.Summary, 1024),
            tags,
            fields,
            DateTimeOffset.UtcNow);
    }

    private static Dictionary<string, string> ValidateSettings(PluginInstance plugin, Dictionary<string, string> values)
    {
        var definitions = plugin.Description?.Settings ?? [];
        var clean = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (SettingDefinition def in definitions)
        {
            if (!values.TryGetValue(def.Key, out string? value))
                continue;

            value ??= "";
            if (value.Length > 4096)
                throw new ArgumentException($"{def.Label}: value is too long.");

            bool ok = def.Type switch
            {
                SettingTypes.Bool => bool.TryParse(value, out _),
                SettingTypes.Int => long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _),
                SettingTypes.Number => double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out _),
                _ => true
            };

            if (!ok)
                throw new ArgumentException($"{def.Label}: '{value}' is not a valid {def.Type}.");

            clean[def.Key] = value;
        }

        return clean;
    }

    private bool IsDisabled(string id)
    {
        lock (_gate) return _settings.DisabledPlugins.Contains(id);
    }

    private void SetDisabled(string id, bool disabled)
    {
        lock (_gate)
        {
            _settings.DisabledPlugins.Remove(id);
            if (disabled)
                _settings.DisabledPlugins.Add(id);
            _settings.Save(_settingsPath);
        }
    }

    private void Log(GuardianLogLevel level, string message) =>
        Raise(LogEmitted, new LogEntry(DateTimeOffset.UtcNow, level, message, "plugins"));

    private void Raise<T>(EventHandler<T>? handler, T args)
    {
        foreach (EventHandler<T> h in handler?.GetInvocationList() ?? [])
        {
            try { h(this, args); } catch { }
        }
    }

    private async Task StopAllAsync()
    {
        await Task.WhenAll(Plugins.Select(p => p.StopAsync()));
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel();
        _analysisQueue.Writer.TryComplete();

        await StopAllAsync();

        if (_analysisWorker is not null)
        {
            try { await _analysisWorker.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
        }

        _lifetime.Dispose();
    }
}
