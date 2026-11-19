using System.Text.Json;
using System.Text.Json.Serialization;

namespace FileGuardian.Protocol;

public static class ProtocolJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        MaxDepth = 32,
        WriteIndented = false // must stay false: one message per line
    };

    public static JsonElement ToElement<T>(T value) =>
        JsonSerializer.SerializeToElement(value, Options);

    public static T FromElement<T>(JsonElement? element)
    {
        if (element is null)
            throw new ProtocolViolationException("Missing payload.");

        return element.Value.Deserialize<T>(Options)
            ?? throw new ProtocolViolationException(
                $"Payload could not be read as {typeof(T).Name}.");
    }
}

public sealed class ProtocolViolationException(string message)
    : Exception(message);
