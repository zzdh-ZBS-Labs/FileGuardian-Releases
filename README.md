# FileGuardian

Malware artifact capture for Windows, developed by ZBS Labs.

FileGuardian watches a selected directory tree and attempts to preserve newly created or modified files before they are deleted. It provides a GUI, a command-line interface, and built-in plugins in one self-contained Windows x64 executable.

FileGuardian is an artifact acquisition tool, not a backup utility, malware detector, sandbox, or sample launcher. It never executes captured files.

## Download

Download the Windows x64 executable from [Releases](https://github.com/zzdh-ZBS-Labs/FileGuardian-Releases/releases). This repository distributes user documentation and release binaries; the application source code is not public.

The Windows executable is self-contained and does not require a separately installed .NET runtime. When a release includes a companion SHA-256 file, compare it with the downloaded executable:

```powershell
Get-FileHash .\FileGuardian.exe -Algorithm SHA256
```

## Features

- **Acquisition first:** Attempts to pin and open candidate files before queued copying or plugin analysis.
- **Session-based collection:** Watches new and modified files; collecting files already present is optional.
- **Versioned evidence:** Preserves original filenames and source-relative paths, with historical versions and a central index.
- **SHA-256 hashing:** Records hashes of the bytes saved.
- **Plugin support:** Includes entropy/file-type triage, extension/path advisories, event export, and plugin panels.

## Quick start

Choose separate, non-overlapping directories for monitored files and evidence. Use the same volume when possible so hard-link pinning is available:

```text
C:\Analysis\          Monitored directory
C:\Evidence\Run01\    Evidence directory
```

1. Start `FileGuardian.exe`.
2. Select the Monitor folder and a separate Capture folder.
3. Leave **Also collect existing files** unchecked unless you want startup collection.
4. Click **Arm artifact capture** and wait for the **Armed** state.
5. Run the sample through your normal analysis workflow.
6. Review the captured artifacts and activity, then stop collection and allow queued work to drain.

Check the existing-file setting before each session because the GUI remembers it. Activity before the Armed state is not reliably covered.

For GUI rendering issues, try:

```powershell
.\FileGuardian.exe --software-rendering
```

### Command line

Start headless collection:

```powershell
.\FileGuardian.exe cli "C:\Analysis" "C:\Evidence\Run01"
```

Wait for the `Armed. Session ...` message before running the sample. Press `Ctrl+C` to stop.

Add `--capture-existing` to collect files already present, `--no-plugins` to disable plugins, or `--verbose` for debug logging. Use `.\FileGuardian.exe --help` for top-level usage.

## Handling evidence

The evidence folder contains the latest copies under `<RootName>\<relative path>`. The `.fileguardian` directory contains historical versions, the central index, and acquisition/recovery data.

Preserve the complete evidence folder. Do not edit stored files, clear their read-only attributes, or modify internal directories; latest copies may share underlying file content with historical versions.

Captured artifacts retain their original names and can remain executable. Do not double-click them or open them in associated applications.

## Plugins

Built-in plugins require no separate installation or approval. External plugins require explicit approval, and changes to their contents invalidate the previous approval.

Plugins run in separate processes but are not sandboxed. They run with the launching user's privileges, so approve only code you trust.

## Limitations

Collection is **best-effort, not guaranteed**. FileGuardian is a user-mode collector, not a kernel minifilter.

- Files can disappear before acquisition; permissions and sharing restrictions can prevent capture.
- Hard-link pins and open handles do not prevent overwrite or truncation.
- File size, queue pressure, available storage, and shutdown deadlines affect collection.
- FileGuardian does not identify the writer process or determine whether a file is malicious.
- Same-user malicious code can interfere with the application, evidence, and plugins.

## Validation and development

Manually tested on Windows for GUI launch, file capture, and capture of short-lived files before deletion. Collection is best-effort, not guaranteed.

Development assisted by Claude Opus 5.5. Static security review assisted by Claude Fable 5.1.
