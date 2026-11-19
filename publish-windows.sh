#!/usr/bin/env bash
# Builds the all-in-one FileGuardian.exe (GUI + CLI + built-in plugins) for Windows x64.
set -euo pipefail
cd "$(dirname "$0")"
OUT="${1:-artifacts/win-x64}"
rm -rf "$OUT"
dotnet publish src/FileGuardian.Gui -c Release -r win-x64 -o "$OUT/tmp" --nologo
mkdir -p "$OUT"; mv "$OUT/tmp/FileGuardian.exe" "$OUT/"; rm -rf "$OUT/tmp"
(cd "$OUT" && sha256sum FileGuardian.exe) | tee "$OUT/FileGuardian.exe.sha256"
