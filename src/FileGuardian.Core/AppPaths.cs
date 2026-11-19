namespace FileGuardian.Core;

/// <summary>Per-user locations. Backup paths match the console version.</summary>
public static class AppPaths
{
    public static string DataRoot
    {
        get
        {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            if (OperatingSystem.IsWindows())
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "FileGuardian");
            }

            if (OperatingSystem.IsMacOS())
                return Path.Combine(home, "Library", "Application Support", "FileGuardian");

            string? xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");

            string dataHome =
                !string.IsNullOrWhiteSpace(xdg) && Path.IsPathFullyQualified(xdg)
                    ? xdg
                    : Path.Combine(home, ".local", "share");

            return Path.Combine(dataHome, "fileguardian");
        }
    }

    private static bool LowerCase => !OperatingSystem.IsWindows() && !OperatingSystem.IsMacOS();

    public static string DefaultBackupDirectory =>
        Path.Combine(DataRoot, LowerCase ? "backup" : "Backup");

    public static string DefaultPluginsDirectory =>
        Path.Combine(DataRoot, LowerCase ? "plugins" : "Plugins");

    public static string SettingsFile => Path.Combine(DataRoot, "settings.json");

    public static string TrustStoreFile => Path.Combine(DataRoot, "trusted-plugins.json");
}
