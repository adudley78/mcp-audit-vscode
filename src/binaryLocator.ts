/**
 * Auto-detect the mcp-audit binary path.
 *
 * Resolution order (mirrors the install instructions):
 *  1. `mcp-audit.binaryPath` workspace/user setting (explicit override)
 *  2. `mcp-audit` / `mcp-audit.exe` on PATH  (via `which` / `where`)
 *  3. Common install directories (platform-specific)
 */

import * as cp from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';

const IS_WINDOWS = process.platform === 'win32';

/** Common install paths checked after PATH lookup fails. */
function candidatePaths(): string[] {
  const home = os.homedir();
  if (IS_WINDOWS) {
    const localAppData = process.env['LOCALAPPDATA'] ?? '';
    return [
      path.join(localAppData, 'Programs', 'mcp-audit', 'mcp-audit.exe'),
      path.join(home, '.local', 'bin', 'mcp-audit.exe'),
    ];
  }
  return [
    path.join(home, '.local', 'bin', 'mcp-audit'),
    '/usr/local/bin/mcp-audit',
    path.join(home, '.cargo', 'bin', 'mcp-audit'),
  ];
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
 * Ask the OS where `mcp-audit` lives on PATH.
 * Uses `spawnSync` with list-form args (no shell interpolation).
 * Returns the trimmed path string, or `undefined` if not found.
 */
function whichSync(): string | undefined {
  const cmd = IS_WINDOWS ? 'where' : 'which';
  const binary = IS_WINDOWS ? 'mcp-audit.exe' : 'mcp-audit';
  try {
    const result = cp.spawnSync(cmd, [binary], {
      encoding: 'utf8',
      timeout: 3_000,
      windowsHide: true,
    });
    if (result.status !== 0 || !result.stdout) return undefined;
    // `where` on Windows may return multiple matches; take the first line.
    const first = result.stdout.trim().split(/\r?\n/)[0];
    return first && isExecutable(first) ? first : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Locate the mcp-audit binary.
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
