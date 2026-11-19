using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FileGuardian.Core;
using FileGuardian.Core.Plugins;

namespace FileGuardian.Gui.ViewModels;

public sealed partial class PluginItemViewModel : ObservableObject
{
    private readonly PluginManager _manager;
    private readonly Func<string, string, Task<bool>> _confirm;

    public PluginItemViewModel(PluginInstance instance, PluginManager manager, Func<string, string, Task<bool>> confirm)
    {
        Instance = instance;
        _manager = manager;
        _confirm = confirm;
        Refresh();
    }

    public PluginInstance Instance { get; }
    public string Id => Instance.Id;
    public string Folder => Instance.Manifest.Directory;
    public string Executable => Instance.Manifest.IsBuiltIn
        ? $"{Instance.Manifest.ExecutablePath} {string.Join(' ', Instance.Manifest.Arguments)}"
        : Instance.Manifest.ExecutablePath;
    public bool IsBuiltIn => Instance.Manifest.IsBuiltIn;
    public bool CanRevoke => !IsUntrusted && !IsBuiltIn;
    public string Origin => IsBuiltIn ? "Built-in (separate process)" : "External plugin";

    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _version = "";
    [ObservableProperty] private string _description = "";
    [ObservableProperty] private string _capabilities = "";
    [ObservableProperty] private string _stateText = "";
    [ObservableProperty] private string _lastError = "";
    [ObservableProperty] private string _digest = "";
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEnable))]
    private bool _isRunning;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEnable), nameof(CanRevoke))]
    private bool _isUntrusted;

    public bool CanEnable => !IsRunning && !IsUntrusted;
    [ObservableProperty] private bool _hasSettings;

    public ObservableCollection<SettingFieldViewModel> Settings { get; } = [];

    /// <summary>Re-reads state from the instance. Call on the UI thread.</summary>
    public void Refresh()
    {
        PluginInstance p = Instance;
        Name = TextSanitizer.ForDisplay(p.DisplayName, 100);
        Version = TextSanitizer.ForDisplay(p.Description?.Version ?? "—", 32);
        Description = TextSanitizer.ForDisplay(p.Description?.Description, 1024);
        Capabilities = p.Description is null ? "—" : string.Join(", ", p.Description.Capabilities);
        StateText = p.State.ToString();
        LastError = TextSanitizer.ForDisplay(p.LastError, 1024);
        Digest = p.Manifest.IsBuiltIn
            ? "Integrity: built into FileGuardian.exe (no separate approval needed)"
            : $"Folder SHA-256: {p.CurrentDigest ?? "—"}";
        IsRunning = p.State == PluginState.Running;
        IsUntrusted = p.State == PluginState.Untrusted;

        // Only rebuild the form when the definitions change, so typing isn't lost.
        var definitions = p.Description?.Settings ?? [];
        if (!definitions.Select(d => d.Key).SequenceEqual(Settings.Select(s => s.Key)))
        {
            Dictionary<string, string> values = _manager.GetSettings(p.Id);
            Settings.Clear();
            foreach (var def in definitions)
                Settings.Add(new SettingFieldViewModel(def, values.GetValueOrDefault(def.Key)));
        }

        HasSettings = Settings.Count > 0;
    }

    [RelayCommand]
    private async Task ApproveAsync()
    {
        string digest;
        try
        {
            digest = await Task.Run(() => PluginTrustStore.ComputeDirectoryDigest(Folder));
        }
        catch (Exception ex)
        {
            StatusMessage = ex.Message;
            return;
        }

        bool ok = await _confirm(
            "Approve plugin?",
            $"Plugin id:  {Id}\nFolder:     {Folder}\nExecutable: {Executable}\n\n" +
            $"Folder SHA-256:\n{digest}\n\n" +
            "This plugin will run as a separate process under your account. " +
            "Approve only builds you trust. Any later change to its files will require re-approval.");

        if (!ok) return;
        await RunAsync(() => _manager.TrustAsync(Instance), "Approved.");
    }

    [RelayCommand]
    private Task RevokeAsync() => RunAsync(() => _manager.RevokeAsync(Instance), "Approval revoked.");

    [RelayCommand]
    private Task EnableAsync() => RunAsync(() => _manager.SetEnabledAsync(Instance, true), "Enabled.");

    [RelayCommand]
    private Task DisableAsync() => RunAsync(() => _manager.SetEnabledAsync(Instance, false), "Disabled.");

    [RelayCommand]
    private Task RestartAsync() => RunAsync(() => _manager.RestartAsync(Instance), "Restarted.");

    [RelayCommand]
    private Task SaveSettingsAsync() => RunAsync(
        () => _manager.UpdateSettingsAsync(Instance, Settings.ToDictionary(s => s.Key, s => s.Value)),
        "Settings saved.");

    private async Task RunAsync(Func<Task> action, string success)
    {
        try
        {
            StatusMessage = "Working…";
            await Task.Run(action);
            StatusMessage = success;
        }
        catch (Exception ex)
        {
            StatusMessage = TextSanitizer.ForDisplay(ex.Message, 512);
        }

        Refresh();
    }
}
