using System.Runtime.InteropServices;
using Avalonia;
using FileGuardian.Cli;
using FileGuardian.Core.Plugins;
using FileGuardian.Plugin.Sdk;

namespace FileGuardian.Gui;

/// <summary>
/// One executable, three modes:
///   FileGuardian.exe                         GUI
///   FileGuardian.exe cli &lt;monitor&gt; [backup] ...   headless CLI
///   FileGuardian.exe plugins list|trust|revoke  plugin management
///   FileGuardian.exe --plugin-host &lt;id&gt;       internal: run a built-in plugin
/// </summary>
internal static partial class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length >= 2 && args[0] == PluginManifest.BuiltInPluginArgument)
            return RunBuiltInPlugin(args[1]);

        if (args.Length >= 1)
        {
            switch (args[0])
            {
                case "cli":
                    return CliApp.RunAsync(args[1..], BuiltInPlugins.Manifests(), "FileGuardian.exe cli")
                        .GetAwaiter().GetResult();

                case "plugins" or "migrate":
                    return CliApp.RunAsync(args, BuiltInPlugins.Manifests(), "FileGuardian.exe")
                        .GetAwaiter().GetResult();

                case "-h" or "--help" or "/?":
                    Console.WriteLine(
                        "FileGuardian.exe                                   Start the GUI\n" +
                        "FileGuardian.exe --software-rendering              GUI without GPU acceleration (VMs, RDP)\n" +
                        "FileGuardian.exe cli <monitor> [capture-folder] [--capture-existing] [--hold-delete] [--plugins <dir>] [--no-plugins] [--verbose]\n" +
                        "FileGuardian.exe plugins list | trust <id> | revoke <id>\n" +
                        "FileGuardian.exe migrate [backup]                  Convert old-format captures");
                    return 0;
            }
        }

        HideOwnedConsole();
        return BuildAvaloniaApp(args).StartWithClassicDesktopLifetime(args);
    }

    // Used by the XAML previewer.
    public static AppBuilder BuildAvaloniaApp() => BuildAvaloniaApp([]);

    private static AppBuilder BuildAvaloniaApp(string[] args)
    {
        AppBuilder builder = AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();

        // Analysis VMs, RDP sessions and headless X servers often have no
        // usable GPU. --software-rendering (or FILEGUARDIAN_SOFTWARE_RENDERING=1)
        // skips OpenGL/ANGLE and renders on the CPU.
        bool software = args.Contains("--software-rendering") ||
                        Environment.GetEnvironmentVariable("FILEGUARDIAN_SOFTWARE_RENDERING") == "1";

        if (software)
        {
            builder = builder
                .With(new X11PlatformOptions { RenderingMode = [X11RenderingMode.Software] })
                .With(new Win32PlatformOptions { RenderingMode = [Win32RenderingMode.Software] })
                .With(new AvaloniaNativePlatformOptions { RenderingMode = [AvaloniaNativeRenderingMode.Software] });
        }

        return builder;
    }

    private static int RunBuiltInPlugin(string id)
    {
        FileGuardianPlugin? plugin = BuiltInPlugins.Create(id);
        if (plugin is null)
        {
            Console.Error.WriteLine($"Unknown built-in plugin '{id}'.");
            return 2;
        }

        return PluginRunner.RunAsync(plugin).GetAwaiter().GetResult();
    }

    /// <summary>
    /// When double-clicked, Windows creates a console just for this process;
    /// release it so only the GUI window remains. When started from an
    /// existing terminal, the console is shared and left alone.
    /// </summary>
    private static void HideOwnedConsole()
    {
        if (!OperatingSystem.IsWindows())
            return;

        Span<uint> pids = stackalloc uint[2];
        unsafe
        {
            fixed (uint* p = pids)
            {
                if (GetConsoleProcessList(p, 2) == 1)
                    FreeConsole();
            }
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static unsafe partial uint GetConsoleProcessList(uint* processList, uint count);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FreeConsole();
}
