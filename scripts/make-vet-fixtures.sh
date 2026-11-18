#!/usr/bin/env bash
# Save real answers of `credenzo vet --format json` as test fixtures.
#
# The unit tests of the adapter read these files, so the tests see the form
# that the real command prints. Run this script again after a Credenzo release
# that changes the verdict document, and read the diff.
#
# Use: scripts/make-vet-fixtures.sh [path-to-credenzo]
set -euo pipefail

BIN="${1:-credenzo}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/test/fixtures/vet"
mkdir -p "$OUT"

save() { # file ecosystem package
  # Exit code 1 comes with a verdict document. Exit code 2 is an error.
  local code=0
  "$BIN" vet --format json --ecosystem "$2" -- "$3" > "$OUT/$1.json" || code=$?
  if [ "$code" -gt 1 ]; then
    echo "credenzo vet failed for $3 (exit $code)" >&2
    exit 1
  fi
}

save verified-unpinned npm  "@modelcontextprotocol/server-filesystem"
save verified-pypi     pypi "mcp-server-fetch"
save cve-pinned        npm  "mcp-remote@0.1.30"
save cve-unpinned      npm  "mcp-remote"
save typosquat         npm  "@modelcontextprotocol/server-filesytem"
save unknown           npm  "not-a-real-pkg-zz"
save malicious         pypi "claude-lite"

"$BIN" version > "$OUT/VERSION.txt" 2>/dev/null || "$BIN" --version > "$OUT/VERSION.txt"
echo "Saved to $OUT"
