#!/usr/bin/env bash
# Publishes the sample plugins into the per-user plugin folder.
# Each plugin must then be approved (GUI: Plugins tab > Approve, or CLI: FileGuardian plugins trust <id>).
set -euo pipefail
cd "$(dirname "$0")"
if [[ "$(uname)" == "Darwin" ]]; then
  DEST="${1:-$HOME/Library/Application Support/FileGuardian/Plugins}"
else
  DEST="${1:-${XDG_DATA_HOME:-$HOME/.local/share}/fileguardian/plugins}"
fi
for dir in plugins/*/; do
  name="$(basename "$dir")"; name="${name#FileGuardian.Plugins.}"
  rm -rf "$DEST/$name"
  dotnet publish "$dir" -c Release -o "$DEST/$name" --nologo
  echo "Published $name -> $DEST/$name"
done
