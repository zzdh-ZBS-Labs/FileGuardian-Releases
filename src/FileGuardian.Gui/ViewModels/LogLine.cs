using Avalonia.Media;
using FileGuardian.Core;

namespace FileGuardian.Gui.ViewModels;

public sealed class LogLine(LogEntry entry)
{
    public string Text { get; } =
        $"{entry.TimestampUtc.ToLocalTime():HH:mm:ss.fff}  {entry.LevelText,-7}  " +
        (entry.Source == "engine" ? "" : $"[{TextSanitizer.ForDisplay(entry.Source, 64)}] ") +
        TextSanitizer.ForDisplay(entry.Message, 4000);

    public IBrush Brush { get; } = entry.Level switch
    {
        // Chosen for at least 4.5:1 contrast on the light log background.
        GuardianLogLevel.Error => Error,
        GuardianLogLevel.Warn => Warn,
        GuardianLogLevel.Capture => Capture,
        GuardianLogLevel.Debug => Debug,
        _ => Info
    };

    private static readonly IBrush Error = new SolidColorBrush(Color.Parse("#B42318"));
    private static readonly IBrush Warn = new SolidColorBrush(Color.Parse("#8A5300"));
    private static readonly IBrush Capture = new SolidColorBrush(Color.Parse("#1B6B3A"));
    private static readonly IBrush Debug = new SolidColorBrush(Color.Parse("#5F6672"));
    private static readonly IBrush Info = new SolidColorBrush(Color.Parse("#072034"));
}
