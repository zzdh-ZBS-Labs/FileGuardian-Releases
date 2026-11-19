using System.Text.Json;

namespace FileGuardian.Core.Plugins;

/// <summary>User settings shared by the GUI and CLI.</summary>
public sealed class AppSettings
{
    public string? MonitorDirectory { get; set; }
    public string? BackupDirectory { get; set; }
    public string? PluginsDirectory { get; set; }
    public bool CaptureExistingFiles { get; set; }
    public bool HoldDelete { get; set; }
    public List<string> DisabledPlugins { get; set; } = [];
    public Dictionary<string, Dictionary<string, string>> PluginSettings { get; set; } = [];

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public static AppSettings Load(string path)
    {
        try
        {
            if (File.Exists(path))
                return JsonSerializer.Deserialize<AppSettings>(
                    CaptureStore.ReadCapped(path, 1024 * 1024), Options) ?? new AppSettings();
        }
        catch (Exception ex) when (ex is JsonException or IOException or InvalidDataException)
        {
            // Fall back to defaults; never block startup on a bad settings file.
        }

        return new AppSettings();
    }

    public void Save(string path) => AtomicFile.WriteAllText(path, JsonSerializer.Serialize(this, Options));
}
