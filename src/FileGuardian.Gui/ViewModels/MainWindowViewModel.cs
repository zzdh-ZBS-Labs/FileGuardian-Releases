using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FileGuardian.Core;
using FileGuardian.Core.Plugins;
using FileGuardian.Protocol;

namespace FileGuardian.Gui.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject
{
    private const int MaxLogLines = 5000;
    private const int MaxCaptures = 2000;

    private readonly ConcurrentQueue<LogEntry> _pendingLogs = new();
    private readonly DispatcherTimer _logFlush;
    private AppSettings _settings = new();
    private PluginManager? _plugins;
    private GuardianEngine? _engine;
    private CancellationTokenSource? _stop;
    private Task<GuardianExitReason>? _run;

    public MainWindowViewModel()
    {
        // Engine threads can log thousands of lines per second; batch them
        // onto the UI thread instead of posting one dispatcher call per line.
        _logFlush = new DispatcherTimer(TimeSpan.FromMilliseconds(250), DispatcherPriority.Background, (_, _) => FlushLogs());
        _logFlush.Start();
    }

    /// <summary>Set by the view; shows a modal confirmation.</summary>
    public Func<string, string, Task<bool>> Confirm { get; set; } = (_, _) => Task.FromResult(false);

    public ObservableCollection<LogLine> LogLines { get; } = [];
    public ObservableCollection<CaptureItemViewModel> Captures { get; } = [];
    public ObservableCollection<PluginItemViewModel> Plugins { get; } = [];
    public ObservableCollection<PanelTabViewModel> PanelTabs { get; } = [];

    [ObservableProperty] private string _monitorDirectory = "";
    [ObservableProperty] private string _backupDirectory = "";
    [ObservableProperty] private string _pluginsDirectory = "";
    [ObservableProperty] private string _statusText = "Idle";
    [ObservableProperty] private bool _captureExistingFiles;
    /// <summary>Withhold delete sharing while an artifact is open; the sample can observe this.</summary>
    [ObservableProperty] private bool _holdDelete;
    [ObservableProperty] private bool _showDebug;
    [ObservableProperty] private CaptureItemViewModel? _selectedCapture;
    [ObservableProperty] private PluginItemViewModel? _selectedPlugin;
    [ObservableProperty] private PanelTabViewModel? _selectedPanel;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartCommand), nameof(StopCommand))]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    private bool _isRunning;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartCommand), nameof(StopCommand))]
    private bool _isBusy;

    public bool IsIdle => !IsRunning;

    /// <summary>Short session state shown in the header badge.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsArmed), nameof(IsPreparing), nameof(IsStopping), nameof(IsInactive))]
    private string _sessionState = "Idle";

    public bool IsArmed => SessionState == "Armed";
    public bool IsPreparing => SessionState == "Preparing";
    public bool IsStopping => SessionState == "Stopping";
    public bool IsInactive => !IsArmed && !IsPreparing && !IsStopping;

    public string AppVersion { get; } =
        "Version " + (typeof(MainWindowViewModel).Assembly.GetName().Version?.ToString(3) ?? "?");

    // ------------------------------------------------------------------ startup / shutdown

    public async Task InitializeAsync()
    {
        _settings = AppSettings.Load(AppPaths.SettingsFile);
        MonitorDirectory = _settings.MonitorDirectory ?? "";
        BackupDirectory = _settings.BackupDirectory ?? AppPaths.DefaultBackupDirectory;
        CaptureExistingFiles = _settings.CaptureExistingFiles;
        HoldDelete = _settings.HoldDelete;
        PluginsDirectory = _settings.PluginsDirectory ?? AppPaths.DefaultPluginsDirectory;

        _plugins = new PluginManager(
            PluginsDirectory, new PluginTrustStore(AppPaths.TrustStoreFile), _settings, AppPaths.SettingsFile,
            builtIns: BuiltInPlugins.Manifests());

        _plugins.LogEmitted += (_, e) => EnqueueLog(e);
        _plugins.PluginsChanged += (_, _) => Dispatcher.UIThread.Post(RebuildPlugins);
        _plugins.PluginStateChanged += (_, p) => Dispatcher.UIThread.Post(() => OnPluginStateChanged(p));
        _plugins.PanelChanged += (_, p) => Dispatcher.UIThread.Post(() =>
            PanelTabs.FirstOrDefault(t => t.Id == p.Id)?.RequestRefresh());
        _plugins.AnalysisCompleted += (_, e) => Dispatcher.UIThread.Post(() =>
            Captures.FirstOrDefault(c => c.CaptureId == e.Capture.Metadata.CaptureId)?.Apply(e.Analysis));

        await LoadCapturesAsync();

        try
        {
            await Task.Run(() => _plugins.LoadAsync());
        }
        catch (Exception ex)
        {
            EnqueueLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Error, $"Plugin load failed: {ex.Message}", "plugins"));
        }
    }

    /// <summary>Called by the window before it closes.</summary>
    public async Task ShutdownAsync()
    {
        if (IsRunning)
            await StopAsync();

        if (_plugins is not null)
            await _plugins.DisposeAsync();

        _logFlush.Stop();
    }

    // ------------------------------------------------------------------ commands

    private bool CanStart() => !IsRunning && !IsBusy;
    private bool CanStop() => IsRunning && !IsBusy;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task StartAsync()
    {
        GuardianEngine engine;
        try
        {
            engine = new GuardianEngine(new GuardianOptions
            {
                MonitorDirectory = MonitorDirectory,
                BackupDirectory = string.IsNullOrWhiteSpace(BackupDirectory) ? null : BackupDirectory,
                CaptureExistingFiles = CaptureExistingFiles,
                DenyDeleteWhileOpen = HoldDelete
            }, _plugins);
        }
        catch (Exception ex)
        {
            StatusText = ex.Message;
            return;
        }

        _settings.MonitorDirectory = MonitorDirectory;
        _settings.BackupDirectory = BackupDirectory;
        _settings.CaptureExistingFiles = CaptureExistingFiles;
        _settings.HoldDelete = HoldDelete;
        TrySaveSettings();

        engine.LogEmitted += (_, e) => EnqueueLog(e);
        _ = ShowArmedAsync(engine);
        engine.CaptureCommitted += (_, r) => Dispatcher.UIThread.Post(() => AddCapture(new CaptureItemViewModel(r)));
        _plugins?.AttachEngine(engine);

        _engine = engine;
        _stop = new CancellationTokenSource();
        IsRunning = true;
        SessionState = "Preparing";
        StatusText = "Preparing baseline. Wait for Armed before launching the sample.";

        await LoadCapturesAsync();

        CancellationToken token = _stop.Token;
        _run = Task.Run(() => engine.RunAsync(token));
        _ = ObserveRunAsync(engine, _run);
    }

    private async Task ShowArmedAsync(GuardianEngine engine)
    {
        try
        {
            await engine.Ready;
            Dispatcher.UIThread.Post(() =>
            {
                if (ReferenceEquals(_engine, engine) && IsRunning && SessionState == "Preparing")
                    SessionState = "Armed";
                if (ReferenceEquals(_engine, engine) && IsRunning)
                    StatusText = $"Armed: {(CaptureExistingFiles ? "including existing files" : "new/modified artifacts")}. Session {engine.SessionId[..8]}";
            });
        }
        catch (OperationCanceledException) { }
    }

    [RelayCommand(CanExecute = nameof(CanStop))]
    private async Task StopAsync()
    {
        if (_stop is null || _run is null)
            return;

        IsBusy = true;
        SessionState = "Stopping";
        StatusText = "Stopping: draining queued captures (up to 30 s)…";
        _stop.Cancel();

        try { await _run; }
        catch { /* surfaced by ObserveRunAsync */ }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private Task RefreshCapturesAsync() => LoadCapturesAsync();

    /// <summary>Old one-folder-per-capture entries found in the capture folder.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasLegacy), nameof(LegacyText))]
    private int _legacyCount;

    public bool HasLegacy => LegacyCount > 0;
    public string LegacyText => $"Convert {LegacyCount} old-format capture(s)";

    [RelayCommand]
    private async Task MigrateLegacyAsync()
    {
        if (IsRunning)
        {
            StatusText = "Stop monitoring before converting old captures.";
            return;
        }

        string backup = PathSafety.NormalizeDirectory(
            string.IsNullOrWhiteSpace(BackupDirectory) ? AppPaths.DefaultBackupDirectory : BackupDirectory);

        bool ok = await Confirm("Convert old captures?",
            $"{LegacyCount} capture folder(s) in {backup} will be moved into the new layout:\n\n" +
            "  • each file's newest version appears under its original name and folder\n" +
            $"  • every version is kept under {Path.Combine(CaptureLayout.InternalFolder, CaptureLayout.VersionsFolder)}\n" +
            "  • metadata and plugin results go into the central index\n\n" +
            "Content is moved, not re-copied; SHA-256 values are unchanged. The old folders are removed.");
        if (!ok) return;

        IsBusy = true;
        StatusText = "Converting old captures…";
        try
        {
            var result = await Task.Run(() => CaptureStore.MigrateLegacyAsync(backup,
                m => EnqueueLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Warn, m)), CancellationToken.None));
            StatusText = $"Converted {result.Converted} capture(s)" +
                         (result.Failed > 0 ? $"; {result.Failed} could not be converted (see Activity)." : ".");
        }
        catch (Exception ex)
        {
            StatusText = $"Conversion failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }

        await LoadCapturesAsync();
    }

    [RelayCommand]
    private void AnalyzeSelected()
    {
        if (SelectedCapture is null || _plugins is null)
            return;

        StatusText = _plugins.QueueAnalysis(SelectedCapture.Record)
            ? $"Queued analysis of {SelectedCapture.CaptureId}."
            : "Analysis queue is full.";
    }

    [RelayCommand]
    private async Task ReloadPluginsAsync()
    {
        if (_plugins is null) return;
        if (IsRunning)
        {
            StatusText = "Stop monitoring before reloading plugins.";
            return;
        }

        await Task.Run(() => _plugins.LoadAsync());
    }

    [RelayCommand]
    private void ClearLog() => LogLines.Clear();

    // ------------------------------------------------------------------ helpers

    private async Task ObserveRunAsync(GuardianEngine engine, Task<GuardianExitReason> run)
    {
        GuardianExitReason reason;
        try
        {
            reason = await run;
        }
        catch (Exception ex)
        {
            EnqueueLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Error, ex.Message));
            reason = GuardianExitReason.Failed;
        }

        _plugins?.DetachEngine(engine, reason);

        Dispatcher.UIThread.Post(() =>
        {
            IsRunning = false;
            SessionState = reason == GuardianExitReason.Stopped ? "Idle" : "Stopped";
            _engine = null;
            _stop?.Dispose();
            _stop = null;
            StatusText = reason switch
            {
                GuardianExitReason.Stopped => "Stopped.",
                GuardianExitReason.DrainTimedOut => "Stopped: drain timed out; some queued captures were abandoned.",
                GuardianExitReason.WatcherFault => "Stopped: file watcher failed. See Activity.",
                _ => "Could not start. See Activity."
            };
        });
    }

    private async Task LoadCapturesAsync()
    {
        string backup = string.IsNullOrWhiteSpace(BackupDirectory) ? AppPaths.DefaultBackupDirectory : BackupDirectory;

        try
        {
            var items = await Task.Run(() =>
            {
                string dir = PathSafety.NormalizeDirectory(backup);
                var list = CaptureStore.LoadRecent(dir, 500, w => EnqueueLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Warn, w)))
                    .Select(l => new CaptureItemViewModel(l.Record, l.Analyses, l.IsLatest))
                    .ToList();
                return (list, CaptureStore.CountLegacy(dir));
            });

            Captures.Clear();
            foreach (var item in items.list)
                Captures.Add(item);
            LegacyCount = items.Item2;
        }
        catch (Exception ex)
        {
            EnqueueLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Warn, $"Could not load captures: {ex.Message}"));
        }
    }

    private void AddCapture(CaptureItemViewModel item)
    {
        foreach (CaptureItemViewModel older in Captures.Where(c => c.IsLatest && c.MirrorKey == item.MirrorKey))
            older.IsLatest = false;

        Captures.Insert(0, item);
        while (Captures.Count > MaxCaptures)
            Captures.RemoveAt(Captures.Count - 1);
    }

    private void RebuildPlugins()
    {
        if (_plugins is null) return;

        string? selected = SelectedPlugin?.Id;
        Plugins.Clear();
        foreach (PluginInstance p in _plugins.Plugins)
            Plugins.Add(new PluginItemViewModel(p, _plugins, Confirm));

        SelectedPlugin = Plugins.FirstOrDefault(p => p.Id == selected) ?? Plugins.FirstOrDefault();
        SyncPanelTabs();
    }

    private void OnPluginStateChanged(PluginInstance plugin)
    {
        Plugins.FirstOrDefault(p => p.Id == plugin.Id)?.Refresh();
        SyncPanelTabs();
    }

    private void SyncPanelTabs()
    {
        if (_plugins is null) return;

        var wanted = _plugins.Plugins.Where(p => p.Has(ProtocolConstants.Capabilities.Panel)).ToList();

        foreach (var stale in PanelTabs.Where(t => wanted.All(w => w.Id != t.Id)).ToList())
            PanelTabs.Remove(stale);

        foreach (PluginInstance p in wanted.Where(w => PanelTabs.All(t => t.Id != w.Id)))
        {
            var tab = new PanelTabViewModel(p);
            PanelTabs.Add(tab);
            _ = tab.RefreshAsync();
        }

        SelectedPanel ??= PanelTabs.FirstOrDefault();
    }

    private void EnqueueLog(LogEntry entry)
    {
        if (entry.Level == GuardianLogLevel.Debug && !ShowDebug)
            return;

        _pendingLogs.Enqueue(entry);
    }

    private void FlushLogs()
    {
        int budget = 1000;
        while (budget-- > 0 && _pendingLogs.TryDequeue(out LogEntry? entry))
            LogLines.Add(new LogLine(entry));

        int excess = LogLines.Count - MaxLogLines;
        for (int i = 0; i < excess; i++)
            LogLines.RemoveAt(0);
    }

    private void TrySaveSettings()
    {
        try { _settings.Save(AppPaths.SettingsFile); }
        catch (Exception ex) { StatusText = $"Could not save settings: {ex.Message}"; }
    }
}
