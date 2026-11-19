namespace FileGuardian.Core;

/// <summary>Path helpers carried over unchanged from the console version.</summary>
public static class PathSafety
{
    public static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

    public static readonly StringComparer PathComparer =
        OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;

    public static bool IsSupportedPlatform =>
        OperatingSystem.IsWindows() ||
        OperatingSystem.IsLinux() ||
        OperatingSystem.IsMacOS();

    public static string NormalizeDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("A directory path is required.");

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }

    public static bool IsWithin(string parent, string candidate)
    {
        if (string.Equals(parent, candidate, PathComparison))
            return true;

        string prefix = Path.EndsInDirectorySeparator(parent)
            ? parent
            : parent + Path.DirectorySeparatorChar;

        return candidate.StartsWith(prefix, PathComparison);
    }

    public static bool Overlaps(string a, string b) =>
        IsWithin(a, b) || IsWithin(b, a);

    public static void EnsureNoReparsePoints(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string root = Path.GetPathRoot(fullPath)
            ?? throw new InvalidDataException("Path has no root.");

        Check(root);

        string current = root;
        string remainder = fullPath[root.Length..];

        foreach (string component in remainder.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            Check(current);
        }

        static void Check(string componentPath)
        {
            if ((File.GetAttributes(componentPath) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Symbolic links and reparse points are not allowed: " +
                    componentPath);
            }
        }
    }

    /// <summary>
    /// Resolves a manifest-supplied relative path and guarantees it stays
    /// inside <paramref name="root"/>.
    /// </summary>
    public static string ResolveContained(string root, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative))
            throw new InvalidDataException("Path must be relative.");

        string full = Path.GetFullPath(Path.Combine(root, relative));

        if (!IsWithin(root, full) || string.Equals(root, full, PathComparison))
            throw new InvalidDataException("Path escapes its root directory.");

        return full;
    }
}
