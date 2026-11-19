using System.Diagnostics;
using System.Text.RegularExpressions;
using FileGuardian.Protocol;

namespace FileGuardian.Core.Plugins;

public enum PluginState
{
    Untrusted,
    Disabled,
    Stopped,
    Starting,
    Running,
    Faulted
}

/// <summary>One plugin = one child process. All plugin output is untrusted.</summary>
public sealed partial class PluginInstance
{
    private static readonly TimeSpan InitializeTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(3);

    private readonly Action<LogEntry> _log;
    private readonly object _gate = new();
    private Process? _process;
    private PluginConnection? _connection;
    private bool _stopping;

    internal PluginInstance(PluginManifest manifest, Action<LogEntry> log)
    {
        Manifest = manifest;
        _log = log;
    }

    public PluginManifest Manifest { get; }
    public string Id => Manifest.Id;
    public PluginState State { get; private set; } = PluginState.Stopped;
    public PluginDescription? Description { get; private set; }
    public string? LastError { get; private set; }
    public string? CurrentDigest { get; internal set; }
    internal int RecentFailures { get; set; }
    internal DateTimeOffset FailureWindowStart { get; set; }

    public string DisplayName => Description?.Name ?? Manifest.Name;

    public event Action<PluginInstance>? StateChanged;
    public event Action<PluginInstance>? PanelChanged;

    /// <summary>Raised when a running plugin dies or misbehaves.</summary>
    internal event Action<PluginInstance>? Faulted;

    public bool Has(string capability) =>
        State == PluginState.Running &&
        Description?.Capabilities.Contains(capability) == true;

    internal void SetState(PluginState state, string? error = null)
    {
        lock (_gate)
        {
            State = state;
            if (error is not null || state is PluginState.Running)
                LastError = error;
        }

        StateChanged?.Invoke(this);
    }

    internal async Task StartAsync(Dictionary<string, string> settings, CancellationToken token)
    {
        SetState(PluginState.Starting);
        _stopping = false;

        var psi = new ProcessStartInfo(Manifest.ExecutablePath)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Manifest.Directory
        };

        foreach (string arg in Manifest.Arguments)
            psi.ArgumentList.Add(arg);

        psi.Environment["FILEGUARDIAN_PLUGIN"] = "1";
        psi.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };

        try
        {
            if (!process.Start())
                throw new InvalidOperationException("Process did not start.");
        }
        catch
        {
            process.Dispose();
            throw;
        }

        var connection = new PluginConnection(
            Id, process.StandardOutput.BaseStream, process.StandardInput.BaseStream);

        connection.LogReceived += p => _log(new LogEntry(
            DateTimeOffset.UtcNow, ParseLevel(p.Level), TextSanitizer.ForDisplay(p.Message, 2048), Id));
        connection.PanelChanged += () => PanelChanged?.Invoke(this);
        connection.Closed += reason => OnConnectionClosed(reason);

        lock (_gate)
        {
            _process = process;
            _connection = connection;
        }

        _ = Task.Run(() => PumpStandardErrorAsync(process));
        connection.Start();

        try
        {
            PluginDescription description = await connection.RequestAsync<InitializeParams, PluginDescription>(
                ProtocolConstants.Methods.Initialize,
                new InitializeParams(ProtocolConstants.ProtocolVersion, HostVersion, settings),
                InitializeTimeout,
                token);

            Validate(description);
            Description = description;
            SetState(PluginState.Running);
            _log(Entry(GuardianLogLevel.Info,
                $"Plugin started: {description.Name} {description.Version} " +
                $"[{string.Join(", ", description.Capabilities)}]"));
        }
        catch (Exception ex)
        {
            await StopAsync();
            SetState(PluginState.Faulted, ex.Message);
            throw;
        }
    }

    internal async Task StopAsync()
    {
        PluginConnection? connection;
        Process? process;

        lock (_gate)
        {
            _stopping = true;
            connection = _connection;
            process = _process;
            _connection = null;
            _process = null;
        }

        if (connection is not null)
        {
            try
            {
                await connection.RequestAsync<EmptyResult, EmptyResult>(
                    ProtocolConstants.Methods.Shutdown, EmptyResult.Instance, ShutdownTimeout, CancellationToken.None);
            }
            catch { /* Kill below. */ }

            await connection.DisposeAsync();
        }

        if (process is not null)
        {
            try
            {
                using var wait = new CancellationTokenSource(ShutdownTimeout);
                await process.WaitForExitAsync(wait.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
            }
            finally
            {
                process.Dispose();
            }
        }

        if (State is PluginState.Running or PluginState.Starting)
            SetState(PluginState.Stopped);
    }

    internal Task<FilterResult> FilterAsync(FilterParams p, TimeSpan timeout, CancellationToken token) =>
        Request<FilterParams, FilterResult>(ProtocolConstants.Methods.Filter, p, timeout, token);

    internal Task<AnalyzeResult> AnalyzeAsync(AnalyzeParams p, TimeSpan timeout, CancellationToken token) =>
        Request<AnalyzeParams, AnalyzeResult>(ProtocolConstants.Methods.Analyze, p, timeout, token);

    public async Task<PanelModel> GetPanelAsync(CancellationToken token) =>
        PanelSanitizer.Sanitize(await Request<EmptyResult, PanelModel>(
            ProtocolConstants.Methods.GetPanel, EmptyResult.Instance, TimeSpan.FromSeconds(5), token));

    public async Task<PanelModel> InvokePanelActionAsync(string actionId, CancellationToken token) =>
        PanelSanitizer.Sanitize(await Request<PanelActionParams, PanelModel>(
            ProtocolConstants.Methods.PanelAction, new PanelActionParams(actionId), TimeSpan.FromSeconds(10), token));

    internal Task UpdateSettingsAsync(Dictionary<string, string> settings, CancellationToken token) =>
        Request<UpdateSettingsParams, EmptyResult>(
            ProtocolConstants.Methods.UpdateSettings, new UpdateSettingsParams(settings), TimeSpan.FromSeconds(5), token);

    internal bool TryNotify(HostEvent hostEvent)
    {
        PluginConnection? c;
        lock (_gate) c = _connection;
        return c?.TryNotify(ProtocolConstants.Methods.Event, hostEvent) ?? false;
    }

    private async Task<TResult> Request<TParams, TResult>(
        string method, TParams p, TimeSpan timeout, CancellationToken token)
    {
        PluginConnection c;
        lock (_gate)
            c = _connection ?? throw new InvalidOperationException($"Plugin '{Id}' is not running.");

        try
        {
            return await c.RequestAsync<TParams, TResult>(method, p, timeout, token);
        }
        catch (PluginTimeoutException ex)
        {
            // A hung plugin is treated like a crashed one: kill and let the
            // manager decide whether to restart it.
            Fault(ex.Message);
            throw;
        }
        catch (ProtocolViolationException ex)
        {
            Fault(ex.Message);
            throw;
        }
    }

    private void Fault(string reason)
    {
        _log(Entry(GuardianLogLevel.Error, $"Plugin faulted: {reason}"));
        SetState(PluginState.Faulted, reason);
        _ = StopAsync().ContinueWith(_ => Faulted?.Invoke(this), TaskScheduler.Default);
    }

    private void OnConnectionClosed(Exception? reason)
    {
        bool expected;
        lock (_gate) expected = _stopping;

        if (expected || State is not (PluginState.Running or PluginState.Starting))
            return;

        Fault(reason?.Message ?? "Plugin process exited unexpectedly.");
    }

    private async Task PumpStandardErrorAsync(Process process)
    {
        try
        {
            var reader = new BoundedLineReader(process.StandardError.BaseStream, 4096, truncateOversizedLines: true);
            int lines = 0;
            long windowStart = Environment.TickCount64 / 1000;

            while (await reader.ReadLineAsync(CancellationToken.None) is { } line)
            {
                long second = Environment.TickCount64 / 1000;
                if (second != windowStart) { windowStart = second; lines = 0; }
                if (++lines > 50) continue;

                _log(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Debug,
                    "stderr: " + TextSanitizer.ForDisplay(line, 2048), Id));
            }
        }
        catch
        {
            // Process ended or stream closed.
        }
    }

    private void Validate(PluginDescription d)
    {
        if (d.ProtocolVersion != ProtocolConstants.ProtocolVersion)
            throw new ProtocolViolationException(
                $"Plugin speaks protocol {d.ProtocolVersion}; host requires {ProtocolConstants.ProtocolVersion}.");

        // A plugin cannot claim another plugin's identity (and its trust pin).
        if (!string.Equals(d.Id, Manifest.Id, StringComparison.Ordinal))
            throw new ProtocolViolationException($"Plugin reported id '{TextSanitizer.ForDisplay(d.Id, 64)}' but manifest says '{Manifest.Id}'.");

        if (string.IsNullOrWhiteSpace(d.Name) || d.Name.Length > 100 || d.Version is null || d.Version.Length > 32)
            throw new ProtocolViolationException("Invalid plugin name or version.");

        if (d.Capabilities is null || d.Capabilities.Count == 0 ||
            d.Capabilities.Any(c => !ProtocolConstants.Capabilities.All.Contains(c)))
            throw new ProtocolViolationException("Unknown or missing capabilities.");

        if (d.Settings is { } settings)
        {
            if (settings.Count > 32)
                throw new ProtocolViolationException("Too many settings.");

            foreach (SettingDefinition s in settings)
            {
                if (!SettingKeyPattern().IsMatch(s.Key ?? "") ||
                    !SettingTypes.All.Contains(s.Type ?? "") ||
                    string.IsNullOrWhiteSpace(s.Label) || s.Label.Length > 100 ||
                    (s.DefaultValue?.Length ?? 0) > 4096 || (s.Description?.Length ?? 0) > 1024)
                    throw new ProtocolViolationException($"Invalid setting definition '{TextSanitizer.ForDisplay(s.Key, 64)}'.");
            }
        }
    }

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_.-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex SettingKeyPattern();

    private static string HostVersion =>
        typeof(PluginInstance).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    private LogEntry Entry(GuardianLogLevel level, string message) =>
        new(DateTimeOffset.UtcNow, level, message, Id);

    private static GuardianLogLevel ParseLevel(string? level) => level?.ToLowerInvariant() switch
    {
        "debug" => GuardianLogLevel.Debug,
        "warn" or "warning" => GuardianLogLevel.Warn,
        "error" => GuardianLogLevel.Error,
        _ => GuardianLogLevel.Info
    };
}
