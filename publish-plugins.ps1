# Publishes the sample plugins into the per-user plugin folder.
# Each plugin must then be approved (GUI: Plugins tab > Approve, or CLI: FileGuardian plugins trust <id>).
param(
    [string]$Configuration = "Release",
    [string]$Destination = (Join-Path $env:LOCALAPPDATA "FileGuardian\Plugins")
)
$ErrorActionPreference = "Stop"
Get-ChildItem -Path "$PSScriptRoot\plugins" -Directory | ForEach-Object {
    $name = $_.Name -replace '^FileGuardian\.Plugins\.', ''
    $out = Join-Path $Destination $name
    if (Test-Path $out) { Remove-Item $out -Recurse -Force }
    dotnet publish $_.FullName -c $Configuration -o $out --nologo
    Write-Host "Published $name -> $out"
}
