using CommunityToolkit.Mvvm.ComponentModel;
using FileGuardian.Core;
using FileGuardian.Protocol;

namespace FileGuardian.Gui.ViewModels;

public sealed partial class SettingFieldViewModel : ObservableObject
{
    public SettingFieldViewModel(SettingDefinition definition, string? value)
    {
        Definition = definition;
        _value = value ?? definition.DefaultValue ?? "";
    }

    public SettingDefinition Definition { get; }
    public string Key => Definition.Key;
    public string Label => TextSanitizer.ForDisplay(Definition.Label, 100);
    public string Description => TextSanitizer.ForDisplay(Definition.Description, 1024);
    public bool HasDescription => !string.IsNullOrEmpty(Definition.Description);
    public bool IsBool => Definition.Type == SettingTypes.Bool;
    public bool IsText => !IsBool;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BoolValue))]
    private string _value;

    public bool BoolValue
    {
        get => bool.TryParse(Value, out bool b) && b;
        set => Value = value ? "true" : "false";
    }
}
