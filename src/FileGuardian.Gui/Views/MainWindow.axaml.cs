using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using FileGuardian.Gui.ViewModels;

namespace FileGuardian.Gui.Views;

public partial class MainWindow : Window
{
    private bool _shutdownStarted;
    private bool _shutdownComplete;

    public MainWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is MainWindowViewModel vm)
                vm.Confirm = (title, message) => ConfirmDialog.ShowAsync(this, title, message);
        };
    }

    private MainWindowViewModel? Vm => DataContext as MainWindowViewModel;

    private async void OnBrowseMonitor(object? sender, RoutedEventArgs e)
    {
        if (await PickFolderAsync("Folder to monitor") is { } path && Vm is { } vm)
            vm.MonitorDirectory = path;
    }

    private async void OnBrowseBackup(object? sender, RoutedEventArgs e)
    {
        if (await PickFolderAsync("Folder for captures") is { } path && Vm is { } vm)
            vm.BackupDirectory = path;
    }

    private async Task<string?> PickFolderAsync(string title)
    {
        IReadOnlyList<IStorageFolder> result = await StorageProvider.OpenFolderPickerAsync(
            new FolderPickerOpenOptions { Title = title, AllowMultiple = false });

        return result.Count > 0 ? result[0].TryGetLocalPath() : null;
    }

    /// <summary>
    /// Closing while monitoring must still drain the queue and stop plugin
    /// processes, exactly like Ctrl+C in the console version.
    /// </summary>
    protected override async void OnClosing(WindowClosingEventArgs e)
    {
        if (_shutdownComplete || Vm is null)
        {
            base.OnClosing(e);
            return;
        }

        e.Cancel = true;
        if (_shutdownStarted)
            return;

        _shutdownStarted = true;
        IsEnabled = false;
        Title = "FileGuardian — shutting down…";

        try
        {
            await Vm.ShutdownAsync();
        }
        finally
        {
            _shutdownComplete = true;
            Close();
        }
    }
}
