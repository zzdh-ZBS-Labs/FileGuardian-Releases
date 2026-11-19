using System.Text.Json;
using System.Text.Json.Serialization;

namespace FileGuardian.Protocol;

/// <summary>JSON-RPC 2.0 envelope (request, response, or notification).</summary>
public sealed class RpcMessage
{
    [JsonPropertyName("jsonrpc")]
    public string JsonRpc { get; set; } = "2.0";

    public long? Id { get; set; }
    public string? Method { get; set; }
    public JsonElement? Params { get; set; }
    public JsonElement? Result { get; set; }
    public RpcError? Error { get; set; }

    [JsonIgnore]
    public bool IsRequest => Method is not null && Id is not null;

    [JsonIgnore]
    public bool IsNotification => Method is not null && Id is null;

    [JsonIgnore]
    public bool IsResponse => Method is null && Id is not null;
}

public sealed record RpcError(int Code, string Message);

// ----- initialize -----

public sealed record InitializeParams(
    int ProtocolVersion,
    string HostVersion,
    Dictionary<string, string> Settings);

/// <summary>Returned by the plugin from <c>initialize</c>.</summary>
public sealed record PluginDescription(
    int ProtocolVersion,
    string Id,
    string Name,
    string Version,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<SettingDefinition>? Settings = null,
    string? Description = null);

public sealed record SettingDefinition(
    string Key,
    string Label,
    string Type,
    string? DefaultValue = null,
    string? Description = null);

// ----- pre-capture filter -----

/// <summary>
/// Sent while the host holds the source file open. Contains no content and
/// only the path relative to the monitored directory.
/// </summary>
public sealed record FilterParams(string RelativePath, string Extension, long Length);

public sealed record FilterResult(bool Capture, string? Reason = null);

// ----- post-capture analysis -----

/// <summary>
/// Sent after a capture is committed. <see cref="ContentPath"/> points at
/// the captured copy (marked read-only), never at the live source file.
/// </summary>
public sealed record AnalyzeParams(
    string CaptureId,
    string ContentPath,
    string RelativePath,
    long CapturedLength,
    string Sha256);

public sealed record AnalyzeResult(
    string Verdict,
    string? Summary = null,
    IReadOnlyList<string>? Tags = null,
    Dictionary<string, string>? Fields = null);

// ----- notifications / export -----

public sealed record HostEvent(
    string Kind,
    DateTimeOffset TimestampUtc,
    string? Message = null,
    string? CaptureId = null,
    Dictionary<string, string>? Data = null);

// ----- declarative GUI panels -----

/// <summary>
/// Plugins describe UI as data; the host renders it. Plugins never ship
/// UI code into the host process.
/// </summary>
public sealed record PanelModel(string Title, IReadOnlyList<PanelElement> Elements);

public sealed record PanelElement(
    string Type,
    string? Text = null,
    string? Label = null,
    string? ActionId = null,
    IReadOnlyList<KeyValueItem>? Items = null,
    IReadOnlyList<string>? Columns = null,
    IReadOnlyList<IReadOnlyList<string>>? Rows = null);

public sealed record KeyValueItem(string Key, string Value);

public sealed record PanelActionParams(string ActionId);

public sealed record UpdateSettingsParams(Dictionary<string, string> Settings);

// ----- plugin -> host -----

public sealed record LogParams(string Level, string Message);

public sealed record EmptyResult
{
    public static readonly EmptyResult Instance = new();
}
