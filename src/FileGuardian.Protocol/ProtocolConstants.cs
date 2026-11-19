namespace FileGuardian.Protocol;

/// <summary>
/// Constants shared by the host and plugins. The wire format is
/// newline-delimited JSON-RPC 2.0 over the plugin's stdin/stdout.
/// stderr is reserved for free-form plugin diagnostics.
/// </summary>
public static class ProtocolConstants
{
    public const int ProtocolVersion = 1;

    /// <summary>Hard upper bound on one JSON message, in bytes.</summary>
    public const int MaxMessageBytes = 1024 * 1024;

    public static class Methods
    {
        // Host -> plugin requests
        public const string Initialize = "initialize";
        public const string Filter = "filter";
        public const string Analyze = "analyze";
        public const string GetPanel = "getPanel";
        public const string PanelAction = "panelAction";
        public const string UpdateSettings = "updateSettings";
        public const string Shutdown = "shutdown";

        // Host -> plugin notification
        public const string Event = "event";

        // Plugin -> host notifications (plugins can never issue requests)
        public const string Log = "log";
        public const string PanelChanged = "panelChanged";
    }

    public static class Capabilities
    {
        public const string Filter = "filter";
        public const string Analyze = "analyze";
        public const string Notify = "notify";
        public const string Panel = "panel";

        public static readonly IReadOnlySet<string> All =
            new HashSet<string>(StringComparer.Ordinal)
            { Filter, Analyze, Notify, Panel };
    }

    public static class ErrorCodes
    {
        public const int MethodNotFound = -32601;
        public const int InvalidParams = -32602;
        public const int PluginError = -32000;
    }
}

public static class Verdicts
{
    public const string Info = "info";
    public const string Clean = "clean";
    public const string Suspicious = "suspicious";
    public const string Malicious = "malicious";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.Ordinal)
        { Info, Clean, Suspicious, Malicious };

    /// <summary>Higher is worse; used to pick the headline verdict.</summary>
    public static int Severity(string verdict) => verdict switch
    {
        Malicious => 3,
        Suspicious => 2,
        Clean => 1,
        _ => 0
    };
}

public static class EventKinds
{
    public const string EngineStarted = "engine.started";
    public const string EngineStopped = "engine.stopped";
    public const string CaptureCommitted = "capture.committed";
    public const string AnalysisCompleted = "analysis.completed";
    public const string Warning = "log.warning";
    public const string Error = "log.error";
}

public static class PanelElementTypes
{
    public const string Heading = "heading";
    public const string Text = "text";
    public const string KeyValue = "keyValue";
    public const string Table = "table";
    public const string Button = "button";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.Ordinal)
        { Heading, Text, KeyValue, Table, Button };
}

public static class SettingTypes
{
    public const string String = "string";
    public const string Bool = "bool";
    public const string Int = "int";
    public const string Number = "number";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.Ordinal)
        { String, Bool, Int, Number };
}
