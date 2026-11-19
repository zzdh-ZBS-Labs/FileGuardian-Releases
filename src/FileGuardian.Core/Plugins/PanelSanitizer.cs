using FileGuardian.Protocol;

namespace FileGuardian.Core.Plugins;

/// <summary>
/// Clamps a plugin-supplied panel to sane sizes and strips control/bidi
/// characters before the GUI ever sees it. The GUI renders text only as
/// plain text, never as markup.
/// </summary>
public static class PanelSanitizer
{
    public const int MaxElements = 64;
    public const int MaxRows = 500;
    public const int MaxColumns = 12;
    public const int MaxItems = 64;
    public const int MaxText = 4000;
    public const int MaxCell = 512;

    public static PanelModel Sanitize(PanelModel? model)
    {
        if (model is null)
            return new PanelModel("(empty)", []);

        var elements = new List<PanelElement>();

        foreach (PanelElement e in (model.Elements ?? []).Take(MaxElements))
        {
            if (e is null || !PanelElementTypes.All.Contains(e.Type ?? ""))
                continue;

            elements.Add(e.Type switch
            {
                PanelElementTypes.Heading or PanelElementTypes.Text =>
                    new PanelElement(e.Type, Text: Clean(e.Text, MaxText)),

                PanelElementTypes.Button =>
                    new PanelElement(e.Type,
                        Label: Clean(e.Label ?? e.ActionId, 64),
                        ActionId: TextSanitizer.Truncate(e.ActionId, 64)),

                PanelElementTypes.KeyValue =>
                    new PanelElement(e.Type,
                        Label: Clean(e.Label, 200),
                        Items: (e.Items ?? []).Take(MaxItems)
                            .Where(i => i is not null)
                            .Select(i => new KeyValueItem(Clean(i.Key, 128), Clean(i.Value, MaxCell)))
                            .ToList()),

                _ => SanitizeTable(e)
            });
        }

        return new PanelModel(Clean(model.Title, 64), elements);
    }

    private static PanelElement SanitizeTable(PanelElement e)
    {
        var columns = (e.Columns ?? []).Take(MaxColumns).Select(c => Clean(c, 64)).ToList();
        var rows = (e.Rows ?? [])
            .Take(MaxRows)
            .Where(r => r is not null)
            .Select(r => (IReadOnlyList<string>)r.Take(columns.Count).Select(c => Clean(c, MaxCell)).ToList())
            .ToList();

        return new PanelElement(PanelElementTypes.Table, Label: Clean(e.Label, 200), Columns: columns, Rows: rows);
    }

    private static string Clean(string? s, int max) => TextSanitizer.ForDisplay(s, max);
}
