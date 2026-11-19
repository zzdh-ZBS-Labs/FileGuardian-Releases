using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FileGuardian.Core;
using FileGuardian.Core.Plugins;
using FileGuardian.Protocol;

namespace FileGuardian.Gui.ViewModels;

/// <summary>One tab per running plugin that declared the "panel" capability.</summary>
public sealed partial class PanelTabViewModel(PluginInstance instance) : ObservableObject
{
    private int _refreshQueued;

    public PluginInstance Instance { get; } = instance;
    public string Id => Instance.Id;

    [ObservableProperty] private string _title = TextSanitizer.ForDisplay(instance.DisplayName, 64);
    [ObservableProperty] private PanelModel? _panel;
    [ObservableProperty] private string _error = "";

    [RelayCommand]
    public async Task RefreshAsync()
    {
        try
        {
            PanelModel model = await Instance.GetPanelAsync(CancellationToken.None);
            Panel = model;
            Error = "";
        }
        catch (Exception ex)
        {
            Error = TextSanitizer.ForDisplay(ex.Message, 512);
        }
    }

    /// <summary>Coalesces bursts of panelChanged notifications.</summary>
    public async void RequestRefresh()
    {
        if (Interlocked.Exchange(ref _refreshQueued, 1) != 0)
            return;

        await Task.Delay(300);
        Interlocked.Exchange(ref _refreshQueued, 0);
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task InvokeActionAsync(string? actionId)
    {
        if (string.IsNullOrEmpty(actionId))
            return;

        try
        {
            Panel = await Instance.InvokePanelActionAsync(actionId, CancellationToken.None);
            Error = "";
        }
        catch (Exception ex)
        {
            Error = TextSanitizer.ForDisplay(ex.Message, 512);
        }
    }
}
