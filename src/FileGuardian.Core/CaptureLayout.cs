using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace FileGuardian.Core;

/// <summary>
/// On-disk layout of a backup folder (schema 3).
///
///   Backup/
///     Downloads/                       latest version of each file, exact name,
///       invoice.pdf                    in the same folders as the source
///       tools/setup.exe
///     .fileguardian/                   hidden on Windows
///       index.jsonl                    every capture + every plugin result
///       index.lock                     one writer process at a time
///       roots.json                     monitored folder -> top-level name
///       staging/                       in-progress copies (never published)
///       versions/Downloads/invoice.pdf/2026-11-07 19.03.22Z [ab12cd34]/invoice.pdf
///
/// Version files are immutable once published: they are never moved or
/// renamed, so a plugin reading one cannot be disturbed by a newer capture.
/// The mirror copy is a hard link to the newest version where the file
/// system supports it (no extra space), otherwise a plain copy.
/// </summary>
public static class CaptureLayout
{
    public const string InternalFolder = ".fileguardian";
    public const string VersionsFolder = "versions";
    public const string StagingFolder = "staging";

    /// <summary>
    /// One hard link per acquired file, created inside the watcher callback.
    /// A link pins the file's data: deleting the original name can no longer
    /// destroy the bytes before the copy worker reads them. Entries are
    /// removed as soon as the capture finishes.
    /// </summary>
    public const string LinksFolder = "links";
    public const string IndexFile = "index.jsonl";
    public const string LockFile = "index.lock";
    public const string RootsFile = "roots.json";

    public static string InternalDirectory(string backup) => Path.Combine(backup, InternalFolder);
    public static string VersionsDirectory(string backup) => Path.Combine(backup, InternalFolder, VersionsFolder);
    public static string StagingDirectory(string backup) => Path.Combine(backup, InternalFolder, StagingFolder);
    public static string LinksDirectory(string backup) => Path.Combine(backup, InternalFolder, LinksFolder);
    public static string IndexPath(string backup) => Path.Combine(backup, InternalFolder, IndexFile);

    /// <summary>"2026-11-07 19.03.22Z [ab12cd34]" — sortable, readable, UTC.</summary>
    public static string VersionFolderName(DateTimeOffset startedUtc, string sha256) =>
        string.Create(CultureInfo.InvariantCulture,
            $"{startedUtc.UtcDateTime:yyyy-MM-dd HH.mm.ss}Z [{sha256[..8]}]");

    /// <summary>Index paths are stored with '/' and relative to the backup folder.</summary>
    public static string ToStored(string relative) =>
        relative.Replace(Path.DirectorySeparatorChar, '/');

    /// <summary>
    /// Resolves a path read from index.jsonl. The index is data on disk, so
    /// it must not be able to point outside the backup folder.
    /// </summary>
    public static string Resolve(string backup, string stored)
    {
        if (string.IsNullOrWhiteSpace(stored) || stored.Split('/').Any(s => s is "" or "." or ".."))
            throw new InvalidDataException("Invalid stored path in index.");

        return PathSafety.ResolveContained(backup, stored.Replace('/', Path.DirectorySeparatorChar));
    }

    /// <summary>
    /// Validates a monitor-relative path before it is used to build backup
    /// paths. GetRelativePath of a contained path never yields "..", but the
    /// check is cheap and keeps the invariant local.
    /// </summary>
    internal static string[] SplitRelative(string relative)
    {
        string[] parts = relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length == 0 || parts.Any(p => p is "." or ".."))
            throw new InvalidDataException("Invalid relative path.");

        return parts;
    }

    // ------------------------------------------------------------------ roots

    private sealed record RootEntry(string Monitor, string Name);

    private static readonly JsonSerializerOptions RootsJson = new() { WriteIndented = true };

    /// <summary>
    /// Maps a monitored folder to its top-level name in the backup folder
    /// ("C:\Users\me\Downloads" -> "Downloads"). Two different monitored
    /// folders with the same leaf name get "Downloads (2)". Caller must hold
    /// the index writer lock.
    /// </summary>
    internal static string GetOrAddRootName(string backup, string monitor)
    {
        string path = Path.Combine(InternalDirectory(backup), RootsFile);
        List<RootEntry> roots = File.Exists(path)
            ? JsonSerializer.Deserialize<List<RootEntry>>(CaptureStore.ReadCapped(path, 1024 * 1024)) ?? []
            : [];

        RootEntry? existing = roots.FirstOrDefault(r => string.Equals(r.Monitor, monitor, PathSafety.PathComparison));
        if (existing is not null && IsValidRootName(existing.Name))
            return existing.Name;

        string baseName = SuggestRootName(monitor);
        string name = baseName;
        for (int n = 2; roots.Any(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)); n++)
            name = $"{baseName} ({n})";

        roots.RemoveAll(r => string.Equals(r.Monitor, monitor, PathSafety.PathComparison));
        roots.Add(new RootEntry(monitor, name));

        string temp = path + $".{Guid.NewGuid():N}.tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(roots, RootsJson));
        File.Move(temp, path, overwrite: true);
        return name;
    }

    internal static string SuggestRootName(string monitor)
    {
        string leaf = Path.GetFileName(Path.TrimEndingDirectorySeparator(monitor));

        if (string.IsNullOrEmpty(leaf))
        {
            // A drive or filesystem root: "C:\" -> "C", "/" -> "root".
            string root = (Path.GetPathRoot(monitor) ?? "").TrimEnd('\\', '/', ':');
            leaf = root.Length > 0 && root.All(char.IsLetterOrDigit) ? root : "root";
        }

        return IsValidRootName(leaf) ? leaf : "_" + leaf.TrimStart('.');
    }

    private static bool IsValidRootName(string name) =>
        !string.IsNullOrWhiteSpace(name) &&
        name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 &&
        name is not "." and not ".." &&
        !string.Equals(name, InternalFolder, StringComparison.OrdinalIgnoreCase);

    // ------------------------------------------------------------------ hard links

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkWindows(string newFile, string existingFile, IntPtr securityAttributes);

    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int LinkUnix(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string existing,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string newPath);

    /// <summary>Hard link where supported; false means the caller should copy.</summary>
    internal static bool TryCreateHardLink(string existing, string newPath)
    {
        try
        {
            return OperatingSystem.IsWindows()
                ? CreateHardLinkWindows(newPath, existing, IntPtr.Zero)
                : LinkUnix(existing, newPath) == 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }
}
