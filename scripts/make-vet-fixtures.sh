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

save() { # file ecosystem package [--online]
  # Exit code 1 comes with a verdict document. Exit code 2 is an error.
  local code=0
  "$BIN" vet --format json --ecosystem "$2" ${4:+"$4"} -- "$3" > "$OUT/$1.json" || code=$?
  if [ "$code" -gt 1 ]; then
    echo "credenzo vet failed for $3 (exit $code)" >&2
    exit 1
  fi
}

save verified-unpinned  npm  "@modelcontextprotocol/server-filesystem"
save verified-pypi      pypi "mcp-server-fetch"
save archived           npm  "@modelcontextprotocol/server-github"
save cve-pinned         npm  "mcp-remote@0.1.30"
save cve-unpinned       npm  "mcp-remote"
save typosquat          npm  "@modelcontextprotocol/server-filesytem"
save unknown            npm  "not-a-real-pkg-zz"
# A MAL record that names releases, not the newest one.
save malicious-other    pypi "claude-lite"
# The pinned version is one that the MAL record names.
save malicious-pinned   pypi "litellm==1.82.7"
# The same package, pinned to a version that the record does not name.
save malicious-not-this pypi "litellm==1.83.0"

# Live answers (network). The .txt file is the raw output: when the lookup
# fails, the command prints one message before the document.
save online-listed      npm  "mcp-remote" --online
"$BIN" vet --format json --ecosystem npm --online -- "not-a-real-pkg-zz" > "$OUT/online-fallback.txt" || true

"$BIN" version > "$OUT/VERSION.txt" 2>/dev/null || "$BIN" --version > "$OUT/VERSION.txt"
echo "Saved to $OUT"
