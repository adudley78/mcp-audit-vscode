/**
 * Subprocess wrapper that invokes `mcp-audit scan` and returns parsed JSON.
 *
 * Contracts:
 *  - Spawns with `shell: false` (list-form args, no injection surface).
 *  - Kills the process after SCAN_TIMEOUT_MS and rejects with Error('TIMEOUT').
 *  - Exit code 0 (no findings) and 1 (findings present) are both treated as
 *    success — both produce valid JSON on stdout.
 *  - Exit code 2 (error) rejects so the caller can show a diagnostic.
 *  - All stderr lines are forwarded to `onStderr` for the output channel.
 */

import * as cp from 'child_process';
import { SCAN_TIMEOUT_MS } from './constants';
import type { ScanResult } from './types';

export interface ScanOptions {
  severityThreshold: string;
  /** Injected in tests to replace child_process.spawn. */
  spawnFn?: typeof cp.spawn;
}

/**
 * Run `mcp-audit scan --path <filePath> --format json` and return the parsed
 * `ScanResult`. Rejects on timeout, spawn error, exit code 2, or JSON parse
 * failure.
 */
export function runScan(
  binaryPath: string,
  filePath: string,
  options: ScanOptions,
  onStderr: (line: string) => void
): Promise<ScanResult> {
  return new Promise<ScanResult>((resolve, reject) => {
    const spawnImpl = options.spawnFn ?? cp.spawn;

    const args = [
      'scan',
      '--path',
      filePath,
      '--format',
      'json',
      '--severity-threshold',
      options.severityThreshold,
    ];

    const proc = spawnImpl(binaryPath, args, { shell: false });

    let stdout = '';
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      proc.kill('SIGTERM');
      reject(new Error('TIMEOUT'));
    }, SCAN_TIMEOUT_MS);

    proc.stdout?.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });

    proc.stderr?.on('data', (chunk: Buffer) => {
      const text = chunk.toString('utf8');
      for (const line of text.split(/\r?\n/)) {
        if (line.trim()) onStderr(line);
      }
    });

    proc.on('error', (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(err);
    });

    proc.on('close', (code: number | null) => {
      clearTimeout(timer);
      if (timedOut) return;

      if (code === 2) {
        reject(new Error(`mcp-audit exited with code 2`));
        return;
      }

      // stdout may be empty on some edge cases; treat as no findings.
      if (!stdout.trim()) {
        resolve({ version: '', timestamp: '', findings: [], score: null, errors: [] });
        return;
      }

      try {
        resolve(JSON.parse(stdout) as ScanResult);
      } catch {
        reject(new Error(`Failed to parse mcp-audit output: ${stdout.slice(0, 300)}`));
      }
    });
  });
}
