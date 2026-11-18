/**
 * Auto-detect the Credenzo binary path.
 *
 * The command is `credenzo`. `mcp-audit` is the old name of the same command
 * (releases before 0.33.0 have only that name), so each step looks for
 * `credenzo` first and for `mcp-audit` second.
 *
 * Resolution order (mirrors the install instructions):
 *  1. `mcp-audit.binaryPath` user setting (machine scope; a workspace can not set it)
 *  2. `credenzo` or `mcp-audit` on PATH  (via `which` / `where`)
 *  3. Common install directories (platform-specific)
 */

import * as cp from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';

const IS_WINDOWS = process.platform === 'win32';

/** Command names, in the order they are tried. */
export const BINARY_NAMES = ['credenzo', 'mcp-audit'] as const;

/** Common install paths checked after PATH lookup fails. */
function candidatePaths(): string[] {
  const home = os.homedir();
  const out: string[] = [];
  for (const name of BINARY_NAMES) {
    if (IS_WINDOWS) {
      const localAppData = process.env['LOCALAPPDATA'] ?? '';
      out.push(
        path.join(localAppData, 'Programs', name, `${name}.exe`),
        path.join(home, '.local', 'bin', `${name}.exe`)
      );
      continue;
    }
    out.push(
      path.join(home, '.local', 'bin', name),
      `/usr/local/bin/${name}`,
      path.join(home, '.cargo', 'bin', name),
      `/opt/homebrew/bin/${name}`,
      `/usr/local/opt/python/bin/${name}`,
      `/Library/Frameworks/Python.framework/Versions/3.13/bin/${name}`,
      `/Library/Frameworks/Python.framework/Versions/3.12/bin/${name}`,
      `/Library/Frameworks/Python.framework/Versions/3.11/bin/${name}`,
      `/Library/Frameworks/Python.framework/Versions/3.10/bin/${name}`
    );
  }
  return out;
}

/**
 * Synchronously check if `binaryPath` is an executable file.
 * On Windows we just check existence; Unix also checks the execute bit.
 */
function isExecutable(binaryPath: string): boolean {
  try {
    fs.accessSync(binaryPath, fs.constants.F_OK | (IS_WINDOWS ? 0 : fs.constants.X_OK));
    return true;
  } catch {
    return false;
  }
}

/**
 * Ask the OS where the command lives on PATH (`credenzo`, then `mcp-audit`).
 * Uses `spawnSync` with list-form args (no shell interpolation).
 * Returns the trimmed path string, or `undefined` if not found.
 */
function whichSync(): string | undefined {
  const cmd = IS_WINDOWS ? 'where' : 'which';
  for (const name of BINARY_NAMES) {
    const binary = IS_WINDOWS ? `${name}.exe` : name;
    try {
      const result = cp.spawnSync(cmd, [binary], {
        // `where` on Windows looks in the current directory first. Run it in
        // the home directory, never in a workspace folder.
        cwd: os.homedir(),
        encoding: 'utf8',
        timeout: 3_000,
        windowsHide: true,
      });
      if (result.status !== 0 || !result.stdout) continue;
      // `where` on Windows may return multiple matches; take the first line.
      const first = result.stdout.trim().split(/\r?\n/)[0];
      if (first && isExecutable(first)) return first;
    } catch {
      // Try the next name.
    }
  }
  return undefined;
}

/**
 * Locate the Credenzo binary.
 *
 * Returns `undefined` when the binary cannot be found so the caller can
 * degrade gracefully (show a one-time notification, suppress further errors).
 */
export function locateBinary(): string | undefined {
  const config = vscode.workspace.getConfiguration('mcp-audit');
  const explicit: string = config.get<string>('binaryPath', '').trim();
  if (explicit) {
    return isExecutable(explicit) ? explicit : undefined;
  }

  const fromPath = whichSync();
  if (fromPath) return fromPath;

  for (const candidate of candidatePaths()) {
    if (isExecutable(candidate)) return candidate;
  }

  return undefined;
}
