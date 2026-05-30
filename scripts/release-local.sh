#!/usr/bin/env bash
# WHY THIS SCRIPT EXISTS
# ----------------------
# `code --install-extension foo-0.1.0.vsix` is a silent no-op when version 0.1.0 is
# already installed.  Early development packaged every fix under the same version
# string, so VS Code kept the original (broken) scaffold build.  Two safeguards
# prevent that from happening again:
#   1. Always bump package.json "version" before releasing.
#   2. Explicitly uninstall the old version first, then install with --force.
# --force alone is not enough in all VS Code builds; the uninstall+install combo is
# the only reliable way to guarantee the new VSIX is actually loaded.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

VERSION="$(node -e "console.log(require('./package.json').version)")"
VSIX="mcp-audit-vscode-${VERSION}.vsix"

echo "==> Building (version ${VERSION})..."
npm run build

echo "==> Packaging ${VSIX}..."
npx vsce package

echo "==> Uninstalling any existing install (ignore failure if not installed)..."
code --uninstall-extension mcp-audit.mcp-audit-vscode || true

echo "==> Installing ${VSIX} with --force..."
code --install-extension "${VSIX}" --force

echo "==> Done. Reload VS Code to activate the new version."
