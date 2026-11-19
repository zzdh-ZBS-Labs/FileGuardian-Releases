using System.Runtime.InteropServices;
using System.Text.Json;
using FileGuardian.Core;
using FileGuardian.Core.Plugins;

namespace FileGuardian.Cli;

/// <summary>
/// Headless front end (shared by FileGuardian.Cli and the all-in-one exe). Same engine and plugin host as the GUI, so it can run
/// as a service or scheduled task.
///
///   FileGuardian &lt;monitor-directory&gt; [backup-directory] [--plugins &lt;dir&gt;] [--no-plugins] [--verbose]
///   FileGuardian plugins list    [--plugins &lt;dir&gt;]
///   FileGuardian plugins trust   &lt;id&gt; [--plugins &lt;dir&gt;]
///   FileGuardian plugins revoke  &lt;id&gt;
/// </summary>
public static class CliApp
{
    private static readonly object ConsoleLock = new();
    private static bool _verbose;

    /// <param name="args">Arguments after any mode selector.</param>
    /// <param name="builtIns">Plugins compiled into the host executable.</param>
    /// <param name="commandName">How to invoke this mode, for usage text.</param>
    public static async Task<int> RunAsync(
        string[] args,
        IReadOnlyList<PluginManifest>? builtIns = null,
        string commandName = "FileGuardian")
    {
        builtIns ??= [];
        if (!PathSafety.IsSupportedPlatform)
        {
            WriteLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Error, "Unsupported operating system."));
            return 1;
        }

        var positional = new List<string>();
        string? pluginsDir = null;
        bool noPlugins = false;
        bool captureExisting = false;
        bool holdDelete = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--plugins" when i + 1 < args.Length: pluginsDir = args[++i]; break;
                case "--no-plugins": noPlugins = true; break;
                case "--capture-existing": captureExisting = true; break;
                case "--hold-delete": holdDelete = true; break;
                case "--verbose": _verbose = true; break;
                default: positional.Add(args[i]); break;
            }
        }

        AppSettings settings = AppSettings.Load(AppPaths.SettingsFile);
        pluginsDir ??= settings.PluginsDirectory ?? AppPaths.DefaultPluginsDirectory;

        if (positional.Count > 0 && positional[0] == "migrate")
            return await RunMigrateAsync(positional.Skip(1).ToList(), settings);

        if (positional.Count > 0 && positional[0] == "plugins")
            return await RunPluginCommandAsync(positional.Skip(1).ToList(), pluginsDir, settings, builtIns, commandName);

        if (positional.Count is < 1 or > 2)
        {
            Console.Error.WriteLine(
                $"Usage: {commandName} <monitor-directory> [backup-directory] [--capture-existing] [--hold-delete] [--plugins <dir>] [--no-plugins] [--verbose]\n" +
                $"       {commandName} plugins list|trust <id>|revoke <id>\n" +
                $"       {commandName} migrate [backup-directory]");
            return 1;
        }

        using var stop = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, e) =>
        {
            e.Cancel = true;
            stop.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;

        // Service managers (systemd, launchd, Windows console close) send
        // SIGTERM rather than Ctrl+C; drain gracefully for both.
        using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx =>
        {
            ctx.Cancel = true;
            stop.Cancel();
        });

        PluginManager? plugins = null;

        try
        {
            if (!noPlugins)
            {
                plugins = new PluginManager(pluginsDir, new PluginTrustStore(AppPaths.TrustStoreFile),
                    settings, AppPaths.SettingsFile, builtIns: builtIns);
                plugins.LogEmitted += (_, e) => WriteLog(e);
                await plugins.LoadAsync(stop.Token);
            }

            var engine = new GuardianEngine(
                new GuardianOptions
                {
                    MonitorDirectory = positional[0],
                    BackupDirectory = positional.Count == 2 ? positional[1] : null,
                    CaptureExistingFiles = captureExisting,
                    DenyDeleteWhileOpen = holdDelete
                },
                plugins);

            engine.LogEmitted += (_, e) => WriteLog(e);
            plugins?.AttachEngine(engine);

            WriteLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Info, "Press Ctrl+C to stop."));
            GuardianExitReason reason = await engine.RunAsync(stop.Token);

            plugins?.DetachEngine(engine, reason);
            return reason == GuardianExitReason.Stopped ? 0 : 1;
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
            return 0;
        }
        catch (Exception ex)
        {
            WriteLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Error, ex.Message));
            return 1;
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
            if (plugins is not null)
                await plugins.DisposeAsync(); // lets in-flight analysis finish briefly
        }
    }

    /// <summary>Converts old one-folder-per-capture backups to the current layout.</summary>
    private static async Task<int> RunMigrateAsync(List<string> args, AppSettings settings)
    {
        if (args.Count > 1)
        {
            Console.Error.WriteLine("Usage: migrate [backup-directory]");
            return 1;
        }

        try
        {
            string backup = PathSafety.NormalizeDirectory(
                args.Count == 1 ? args[0] : settings.BackupDirectory ?? AppPaths.DefaultBackupDirectory);

            int count = CaptureStore.CountLegacy(backup);
            WriteLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Info,
                $"Converting {count} old-format capture(s) in {backup}"));

            var result = await CaptureStore.MigrateLegacyAsync(backup,
                m => WriteLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Warn, m)), CancellationToken.None);

            WriteLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Info,
                $"Converted {result.Converted}; already converted {result.AlreadyConverted}; failed {result.Failed}."));
            return result.Failed == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            WriteLog(new LogEntry(DateTimeOffset.UtcNow, GuardianLogLevel.Error, ex.Message));
            return 1;
        }
    }

    private static async Task<int> RunPluginCommandAsync(
        List<string> args, string pluginsDir, AppSettings settings,
        IReadOnlyList<PluginManifest> builtIns, string commandName)
    {
        var trust = new PluginTrustStore(AppPaths.TrustStoreFile);
        var manifests = PluginDiscovery.Discover(pluginsDir, w => Console.Error.WriteLine(w));

        switch (args.FirstOrDefault())
        {
            case "list":
                Console.WriteLine($"Plugins directory: {pluginsDir}");
                foreach (PluginManifest b in builtIns)
                {
                    string state = settings.DisabledPlugins.Contains(b.Id) ? "built-in, disabled" : "built-in";
                    Console.WriteLine($"  {b.Id,-28} {state}");
                }
                foreach (PluginManifest m in manifests.Where(m => builtIns.All(b => b.Id != m.Id)))
                {
                    string digest = PluginTrustStore.ComputeDirectoryDigest(m.Directory);
                    string status = trust.IsTrusted(m.Id, digest) ? "trusted"
                        : trust.GetPinnedDigest(m.Id) is null ? "untrusted" : "CHANGED since approval";
                    if (settings.DisabledPlugins.Contains(m.Id)) status += ", disabled";
                    Console.WriteLine($"  {m.Id,-28} {status,-24} {digest}");
                }
                return 0;

            case "trust" or "revoke" when args.Count == 2 && builtIns.Any(b => b.Id == args[1]):
                Console.WriteLine("Built-in plugins are part of the executable and need no approval.");
                return 0;

            case "trust" when args.Count == 2:
            {
                PluginManifest? m = manifests.FirstOrDefault(x => x.Id == args[1]);
                if (m is null) { Console.Error.WriteLine("No such plugin."); return 1; }

                string digest = PluginTrustStore.ComputeDirectoryDigest(m.Directory);
                Console.WriteLine($"Plugin:     {m.Name} ({m.Id})");
                Console.WriteLine($"Folder:     {m.Directory}");
                Console.WriteLine($"Executable: {m.ExecutablePath}");
                Console.WriteLine($"Digest:     {digest}");
                Console.Write("Approve this exact build? Type 'yes': ");
                if (!string.Equals(Console.ReadLine()?.Trim(), "yes", StringComparison.Ordinal))
                    return 1;

                trust.Trust(m.Id, digest);
                Console.WriteLine("Approved.");
                return 0;
            }

            case "revoke" when args.Count == 2:
                trust.Revoke(args[1]);
                Console.WriteLine("Revoked.");
                return 0;
        }

        await Console.Error.WriteLineAsync($"Usage: {commandName} plugins list|trust <id>|revoke <id>");
        return 1;
    }

    private static void WriteLog(LogEntry e)
    {
        if (e.Level == GuardianLogLevel.Debug && !_verbose)
            return;

        lock (ConsoleLock)
        {
            // Escape control characters from untrusted file names (as before).
            string source = e.Source == "engine" ? "" : $"[{e.Source}] ";
            Console.WriteLine($"{e.TimestampUtc:O} [{e.LevelText}] {source}{JsonSerializer.Serialize(e.Message)}");
        }
    }
}
