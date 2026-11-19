using FileGuardian.Core.Plugins;
using FileGuardian.Plugin.Sdk;

namespace FileGuardian.Gui;

/// <summary>
/// Plugins compiled into the all-in-one executable. Each still runs in its
/// own process: the host starts "FileGuardian.exe --plugin-host &lt;id&gt;".
/// External plugins in the plugins folder continue to work as before.
/// </summary>
internal static class BuiltInPlugins
{
    private static readonly (string Id, string Name, Func<FileGuardianPlugin> Create)[] All =
    [
        ("zbs.entropy", "Entropy & file-type triage", () => new EntropyPlugin()),
        ("zbs.extension-filter", "Extension & path advisory", () => new ExtensionFilterPlugin()),
        ("zbs.jsonl-export", "JSON-lines event export", () => new JsonlExportPlugin())
    ];

    public static IReadOnlyList<PluginManifest> Manifests() =>
        All.Select(p => PluginManifest.BuiltIn(p.Id, p.Name)).ToList();

    public static FileGuardianPlugin? Create(string id) =>
        All.FirstOrDefault(p => p.Id == id).Create?.Invoke();
}
