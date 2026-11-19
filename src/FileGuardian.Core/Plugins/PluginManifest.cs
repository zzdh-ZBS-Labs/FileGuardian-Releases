using System.Text.Json;

namespace FileGuardian.Core.Plugins;

/// <summary>plugin.json as authored on disk.</summary>
public sealed record PluginManifestFile(
    string Id,
    string Name,
    string Executable,
    IReadOnlyList<string>? Arguments = null);

/// <summary>A validated manifest with resolved, contained paths.</summary>
public sealed record PluginManifest(
    string Id,
    string Name,
    string Directory,
    string ExecutablePath,
    IReadOnlyList<string> Arguments,
    bool IsBuiltIn = false)
{
    /// <summary>
    /// A plugin compiled into the host executable. It still runs as a
    /// separate process (the host relaunches itself with
    /// <c>--plugin-host &lt;id&gt;</c>), but it needs no separate approval:
    /// its code is the host's own code, so trusting the host already
    /// covers it.
    /// </summary>
    public static PluginManifest BuiltIn(string id, string name)
    {
        string exe = Environment.ProcessPath
            ?? throw new InvalidOperationException("Cannot determine host executable path.");

        var args = new List<string>();

        // Running as "dotnet FileGuardian.dll" (not apphost / single-file).
        if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            string? entry = System.Reflection.Assembly.GetEntryAssembly()?.Location;
            if (string.IsNullOrEmpty(entry))
                throw new InvalidOperationException("Cannot determine host entry assembly.");
            args.Add(entry);
        }

        args.Add(BuiltInPluginArgument);
        args.Add(id);

        return new PluginManifest(id, name, AppContext.BaseDirectory, exe, args, IsBuiltIn: true);
    }

    public const string BuiltInPluginArgument = "--plugin-host";
}

public static class PluginDiscovery
{
    private const int MaxManifestBytes = 16 * 1024;

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        MaxDepth = 8
    };

    public static IReadOnlyList<PluginManifest> Discover(string pluginsDirectory, Action<string> warn)
    {
        var found = new List<PluginManifest>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        if (!Directory.Exists(pluginsDirectory))
            return found;

        PathSafety.EnsureNoReparsePoints(pluginsDirectory);

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Hidden,
            IgnoreInaccessible = true
        };

        foreach (string dir in Directory.EnumerateDirectories(pluginsDirectory, "*", options))
        {
            try
            {
                PluginManifest manifest = Load(dir);

                if (!seen.Add(manifest.Id))
                {
                    warn($"Duplicate plugin id '{manifest.Id}' in {dir}; ignored.");
                    continue;
                }

                found.Add(manifest);
            }
            catch (FileNotFoundException)
            {
                // Not a plugin folder.
            }
            catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException or UnauthorizedAccessException)
            {
                warn($"Invalid plugin in {dir}: {ex.Message}");
            }
        }

        return found;
    }

    public static PluginManifest Load(string pluginDirectory)
    {
        string dir = PathSafety.NormalizeDirectory(pluginDirectory);
        PathSafety.EnsureNoReparsePoints(dir);

        string manifestPath = Path.Combine(dir, "plugin.json");
        var file = JsonSerializer.Deserialize<PluginManifestFile>(
            CaptureStore.ReadCapped(manifestPath, MaxManifestBytes), Options)
            ?? throw new InvalidDataException("Empty plugin.json.");

        if (string.IsNullOrEmpty(file.Id) || !CaptureStore.PluginIdPattern().IsMatch(file.Id))
            throw new InvalidDataException("Plugin id must match ^[a-z0-9][a-z0-9._-]{0,63}$.");

        if (string.IsNullOrWhiteSpace(file.Name) || file.Name.Length > 100)
            throw new InvalidDataException("Plugin name is missing or too long.");

        string exe = PathSafety.ResolveContained(dir, file.Executable);

        // Allow one manifest to serve all platforms.
        if (OperatingSystem.IsWindows() && !File.Exists(exe) && File.Exists(exe + ".exe"))
            exe += ".exe";

        if (!File.Exists(exe))
            throw new InvalidDataException($"Plugin executable not found: {file.Executable}");

        PathSafety.EnsureNoReparsePoints(exe);

        IReadOnlyList<string> args = file.Arguments ?? [];
        if (args.Count > 16 || args.Any(a => a is null || a.Length > 256))
            throw new InvalidDataException("Too many or too long plugin arguments.");

        return new PluginManifest(file.Id, file.Name, dir, exe, args);
    }
}
