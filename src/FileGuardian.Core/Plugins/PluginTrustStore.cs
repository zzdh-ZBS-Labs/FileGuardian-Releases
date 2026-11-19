using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FileGuardian.Core.Plugins;

/// <summary>
/// Pins each approved plugin to a SHA-256 digest of its entire folder
/// (executable, DLLs, runtimeconfig, everything). Any change to any file
/// un-trusts the plugin until a person re-approves it.
/// </summary>
public sealed class PluginTrustStore
{
    private const int MaxFiles = 5000;
    private const long MaxTotalBytes = 1024L * 1024 * 1024;

    private readonly string _path;
    private readonly object _gate = new();
    private Dictionary<string, string> _pins = new(StringComparer.Ordinal);

    public PluginTrustStore(string path)
    {
        _path = path;
        Load();
    }

    public bool IsTrusted(string pluginId, string digest)
    {
        lock (_gate)
            return _pins.TryGetValue(pluginId, out string? pinned) &&
                   CryptographicOperations.FixedTimeEquals(
                       Encoding.ASCII.GetBytes(pinned), Encoding.ASCII.GetBytes(digest));
    }

    public string? GetPinnedDigest(string pluginId)
    {
        lock (_gate)
            return _pins.GetValueOrDefault(pluginId);
    }

    public void Trust(string pluginId, string digest)
    {
        lock (_gate)
        {
            _pins[pluginId] = digest;
            Save();
        }
    }

    public void Revoke(string pluginId)
    {
        lock (_gate)
        {
            if (_pins.Remove(pluginId))
                Save();
        }
    }

    private void Load()
    {
        if (!File.Exists(_path))
            return;

        var loaded = JsonSerializer.Deserialize<Dictionary<string, string>>(
            CaptureStore.ReadCapped(_path, 256 * 1024));

        if (loaded is not null)
            _pins = new Dictionary<string, string>(loaded, StringComparer.Ordinal);
    }

    private void Save() =>
        AtomicFile.WriteAllText(_path, JsonSerializer.Serialize(_pins, new JsonSerializerOptions { WriteIndented = true }));

    /// <summary>
    /// Digest over sorted (relative path, file SHA-256) pairs. Reparse points
    /// anywhere in the folder are rejected rather than followed.
    /// </summary>
    public static string ComputeDirectoryDigest(string directory)
    {
        string root = PathSafety.NormalizeDirectory(directory);
        PathSafety.EnsureNoReparsePoints(root);

        var files = new List<string>();
        var pending = new Stack<string>();
        pending.Push(root);

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = false,
            AttributesToSkip = 0,
            IgnoreInaccessible = false
        };

        while (pending.Count > 0)
        {
            string dir = pending.Pop();
            foreach (string entry in Directory.EnumerateFileSystemEntries(dir, "*", options))
            {
                FileAttributes attributes = File.GetAttributes(entry);

                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException($"Plugin folder contains a link: {entry}");

                if ((attributes & FileAttributes.Directory) != 0)
                    pending.Push(entry);
                else
                    files.Add(entry);

                if (files.Count > MaxFiles)
                    throw new InvalidDataException("Plugin folder has too many files.");
            }
        }

        var relative = files
            .Select(f => Path.GetRelativePath(root, f).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToList();

        using var outer = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long total = 0;

        foreach (string rel in relative)
        {
            string full = Path.Combine(root, rel);
            using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);

            total += stream.Length;
            if (total > MaxTotalBytes)
                throw new InvalidDataException("Plugin folder is too large to verify.");

            byte[] fileHash = SHA256.HashData(stream);
            outer.AppendData(Encoding.UTF8.GetBytes(rel));
            outer.AppendData([0]);
            outer.AppendData(fileHash);
        }

        return Convert.ToHexString(outer.GetHashAndReset()).ToLowerInvariant();
    }
}

internal static class AtomicFile
{
    public static void WriteAllText(string path, string contents)
    {
        string? dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        string temp = path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllText(temp, contents, new UTF8Encoding(false));
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            try { File.Delete(temp); } catch { }
        }
    }
}
