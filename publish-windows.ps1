# Builds the all-in-one FileGuardian.exe (GUI + CLI + built-in plugins) for Windows x64.
param([string]$Out = "$PSScriptRoot\artifacts\win-x64")
$ErrorActionPreference = "Stop"
if (Test-Path $Out) { Remove-Item $Out -Recurse -Force }
dotnet publish "$PSScriptRoot\src\FileGuardian.Gui" -c Release -r win-x64 -o "$Out\tmp" --nologo
Move-Item "$Out\tmp\FileGuardian.exe" $Out
Remove-Item "$Out\tmp" -Recurse -Force
(Get-FileHash "$Out\FileGuardian.exe" -Algorithm SHA256).Hash.ToLower() | Tee-Object "$Out\FileGuardian.exe.sha256"
