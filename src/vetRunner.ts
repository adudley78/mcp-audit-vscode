/**
 * Subprocess wrapper for `mcp-audit vet` (requires mcp-audit >= 1.1.0).
 *
 * ADR-0002 contract: `mcp-audit vet <name> --format json` is the *only*
 * public interface. Zero detection logic lives in TypeScript — the binary
 * owns all registry lookups, CVE correlations, and typosquat detection.
 *
 * Feature detection:
 *   Call probeVetSupport(binaryPath) once per binary path. If the `vet`
 *   subcommand is absent or the binary pre-dates 1.1.0, supported = false
 *   and the caller should degrade silently.
 *
 * Batching:
 *   When supportsBatch is true, pass all names in a single invocation:
 *     mcp-audit vet name1 name2 ... --format json
 *   The binary returns a JSON array. When batch is not supported, call once
 *   per name and expect a single JSON object or single-element array.
 */

import * as cp from 'child_process';
import { VET_TIMEOUT_MS } from './constants';
import type { VetResult, VetSupportInfo } from './types';

export interface VetOptions {
  /** Pass --online to the binary (gates live registry lookups). */
  online: boolean;
  /** Injected in tests to replace child_process.spawn. */
  spawnFn?: typeof cp.spawn;
}

/**
 * Run `mcp-audit vet --help` synchronously to decide whether the `vet`
 * subcommand exists and whether it accepts multiple names in one call.
 *
 * Never throws — returns { supported: false } on any failure so the
 * caller can degrade gracefully.
 */
export function probeVetSupport(binaryPath: string): VetSupportInfo {
  try {
    const result = cp.spawnSync(binaryPath, ['vet', '--help'], {
      encoding: 'utf8',
      timeout: 3_000,
      windowsHide: true,
    });

    // Null status = process spawn failed; > 1 = hard error (subcommand absent
    // in older CLIs often exits 2 when an unknown subcommand is given).
    if (result.status === null || result.status > 1) {
      return { supported: false, supportsBatch: false };
    }

    const help = (result.stdout ?? '') + (result.stderr ?? '');

    // The help text of a real vet subcommand will mention "vet" or "NAME".
    if (!help.toLowerCase().includes('vet')) {
      return { supported: false, supportsBatch: false };
    }

    // Batch: look for indication that multiple positional NAME args are valid.
    const supportsBatch = /\bnames?\b/i.test(help) || /NAME \[NAME/.test(help);
    return { supported: true, supportsBatch };
  } catch {
    return { supported: false, supportsBatch: false };
  }
}

/**
 * Run `mcp-audit vet <names...> --format json [--online]`.
 *
 * Returns an array of VetResult — one element per name when calling with
 * a single name, or one per name when batch mode is used.
 *
 * Rejects with:
 *  - Error('VET_TIMEOUT') after VET_TIMEOUT_MS
 *  - Error message if exit code > 1 (hard error)
 *  - Parse error if stdout is not valid JSON
 */
export function runVet(
  binaryPath: string,
  names: string[],
  options: VetOptions
): Promise<VetResult[]> {
  return new Promise<VetResult[]>((resolve, reject) => {
    const spawnImpl = options.spawnFn ?? cp.spawn;

    const args = ['vet', ...names, '--format', 'json'];
    if (options.online) args.push('--online');

    const proc = spawnImpl(binaryPath, args, { shell: false });

    let stdout = '';
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      proc.kill('SIGTERM');
      reject(new Error('VET_TIMEOUT'));
    }, VET_TIMEOUT_MS);

    proc.stdout?.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });

    proc.on('error', (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });

    proc.on('close', (code: number | null) => {
      clearTimeout(timer);
      if (timedOut) return;

      // Exit codes 0 (clean) and 1 (findings/warnings) are both success.
      if ((code ?? 0) > 1) {
        reject(new Error(`mcp-audit vet exited with code ${code}`));
        return;
      }

      if (!stdout.trim()) {
        resolve([]);
        return;
      }

      try {
        const parsed = JSON.parse(stdout) as unknown;
        // Normalise: single-name call may return an object, batch returns array.
        resolve(
          Array.isArray(parsed)
            ? (parsed as VetResult[])
            : [parsed as VetResult]
        );
      } catch {
        reject(
          new Error(`Failed to parse vet output: ${stdout.slice(0, 300)}`)
        );
      }
    });
  });
}
