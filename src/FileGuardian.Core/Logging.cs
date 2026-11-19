namespace FileGuardian.Core;

public enum GuardianLogLevel
{
    Debug,
    Info,
    Capture,
    Warn,
    Error
}

public sealed record LogEntry(
    DateTimeOffset TimestampUtc,
    GuardianLogLevel Level,
    string Message,
    string Source = "engine")
{
    public string LevelText => Level switch
    {
        GuardianLogLevel.Debug => "DEBUG",
        GuardianLogLevel.Info => "INFO",
        GuardianLogLevel.Capture => "CAPTURE",
        GuardianLogLevel.Warn => "WARN",
        _ => "ERROR"
    };
}
