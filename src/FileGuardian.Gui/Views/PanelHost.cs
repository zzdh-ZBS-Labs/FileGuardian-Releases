using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using FileGuardian.Protocol;

namespace FileGuardian.Gui.Views;

/// <summary>
/// Renders a plugin's declarative <see cref="PanelModel"/>. Only a fixed set
/// of element types is supported and all text is displayed as plain text.
/// Plugins cannot inject XAML, controls, or code into the host.
/// The model has already been size-clamped by PanelSanitizer in Core.
/// </summary>
public sealed class PanelHost : ContentControl
{
    public static readonly StyledProperty<PanelModel?> ModelProperty =
        AvaloniaProperty.Register<PanelHost, PanelModel?>(nameof(Model));

    public static readonly StyledProperty<ICommand?> ActionCommandProperty =
        AvaloniaProperty.Register<PanelHost, ICommand?>(nameof(ActionCommand));

    public PanelModel? Model
    {
        get => GetValue(ModelProperty);
        set => SetValue(ModelProperty, value);
    }

    public ICommand? ActionCommand
    {
        get => GetValue(ActionCommandProperty);
        set => SetValue(ActionCommandProperty, value);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == ModelProperty || change.Property == ActionCommandProperty)
            Rebuild();
    }

    private void Rebuild()
    {
        var stack = new StackPanel { Spacing = 10 };

        foreach (PanelElement e in Model?.Elements ?? [])
        {
            Control? control = e.Type switch
            {
                PanelElementTypes.Heading => new TextBlock { Text = e.Text, FontSize = 16, FontWeight = FontWeight.SemiBold },
                PanelElementTypes.Text => new SelectableTextBlock { Text = e.Text, TextWrapping = TextWrapping.Wrap },
                PanelElementTypes.KeyValue => BuildKeyValue(e),
                PanelElementTypes.Table => BuildTable(e),
                PanelElementTypes.Button => BuildButton(e),
                _ => null
            };

            if (control is not null)
                stack.Children.Add(control);
        }

        Content = new ScrollViewer
        {
            Content = stack,
            HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto
        };
    }

    private Control BuildButton(PanelElement e)
    {
        var button = new Button
        {
            Content = e.Label,
            Command = ActionCommand,
            CommandParameter = e.ActionId,
            HorizontalAlignment = HorizontalAlignment.Left
        };
        return button;
    }

    private static Control BuildKeyValue(PanelElement e)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 16, RowSpacing = 4 };
        int row = 0;

        foreach (KeyValueItem item in e.Items ?? [])
        {
            grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            var key = new TextBlock { Text = item.Key, FontWeight = FontWeight.SemiBold };
            var value = new SelectableTextBlock { Text = item.Value, TextWrapping = TextWrapping.Wrap };
            Grid.SetRow(key, row);
            Grid.SetRow(value, row);
            Grid.SetColumn(value, 1);
            grid.Children.Add(key);
            grid.Children.Add(value);
            row++;
        }

        return WithLabel(e.Label, grid);
    }

    private static Control BuildTable(PanelElement e)
    {
        IReadOnlyList<string> columns = e.Columns ?? [];
        var grid = new Grid { ColumnSpacing = 16, RowSpacing = 2 };

        foreach (string _ in columns)
            grid.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Auto));

        grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        for (int c = 0; c < columns.Count; c++)
            AddCell(grid, 0, c, columns[c], header: true);

        int r = 1;
        foreach (IReadOnlyList<string> row in e.Rows ?? [])
        {
            grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            for (int c = 0; c < row.Count && c < columns.Count; c++)
                AddCell(grid, r, c, row[c], header: false);
            r++;
        }

        if (r == 1)
        {
            grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            AddCell(grid, 1, 0, "(no rows)", header: false);
        }

        return WithLabel(e.Label, grid);
    }

    private static void AddCell(Grid grid, int row, int column, string text, bool header)
    {
        var cell = new SelectableTextBlock
        {
            Text = text,
            FontWeight = header ? FontWeight.SemiBold : FontWeight.Normal,
            MaxWidth = 480,
            TextTrimming = TextTrimming.CharacterEllipsis
        };
        Grid.SetRow(cell, row);
        Grid.SetColumn(cell, column);
        grid.Children.Add(cell);
    }

    private static Control WithLabel(string? label, Control content)
    {
        if (string.IsNullOrEmpty(label))
            return content;

        return new StackPanel
        {
            Spacing = 4,
            Children = { new TextBlock { Text = label, FontWeight = FontWeight.SemiBold, Opacity = 0.85 }, content }
        };
    }
}
