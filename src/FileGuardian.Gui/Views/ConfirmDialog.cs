using Avalonia.Controls;
using Avalonia.Layout;

namespace FileGuardian.Gui.Views;

/// <summary>Minimal modal Yes/No dialog built in code.</summary>
public static class ConfirmDialog
{
    public static async Task<bool> ShowAsync(Window owner, string title, string message)
    {
        var dialog = new Window
        {
            Title = title,
            Width = 680,
            SizeToContent = SizeToContent.Height,
            CanResize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };

        var yes = new Button { Content = "Approve", Classes = { "accent" } };
        var no = new Button { Content = "Cancel", IsDefault = true };
        yes.Click += (_, _) => dialog.Close(true);
        no.Click += (_, _) => dialog.Close(false);

        dialog.Content = new StackPanel
        {
            Margin = new Avalonia.Thickness(16),
            Spacing = 14,
            Children =
            {
                new SelectableTextBlock
                {
                    Text = message,
                    TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                    FontFamily = new Avalonia.Media.FontFamily("Cascadia Mono,Consolas,Menlo,DejaVu Sans Mono,monospace")
                },
                new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    HorizontalAlignment = HorizontalAlignment.Right,
                    Spacing = 8,
                    Children = { no, yes }
                }
            }
        };

        return await dialog.ShowDialog<bool>(owner);
    }
}
