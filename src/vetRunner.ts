/**
 * Subprocess wrapper for `credenzo vet`.
 *
 * `credenzo vet <package> --format json` takes one package and prints one
 * verdict document. Exit code 0 and exit code 1 both come with a document
 * (1: an open CVE, a typosquat suspicion or a malicious record). Exit code 2
 * is an error.
 *
 * The extension makes no finding of its own: the binary owns the registry
 * lookup, the CVE match and the typosquat check. `verdictAdapter.ts` reads
 * the document.
 *
 * No `vscode` import: the contract test runs this file in plain Node.
 */

import * as cp from 'child_process';
import { VET_TIMEOUT_MS } from './constants';
import { vetSpec } from './launchPackage';
import type { LaunchPackage } from './launchPackage';
import type { VetSupportInfo } from './types';

export interface VetOptions {
  /** Pass --online to the binary (gates live registry lookups). */
  online: boolean;
  /** Injected in tests to replace child_process.spawn. */
  spawnFn?: typeof cp.spawn;
}

/**
 * Run `credenzo vet --help` synchronously to decide whether the `vet`
 * subcommand exists.
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

    // Null status = process spawn failed; > 1 = hard error (an unknown
    // subcommand exits 2).
    if (result.status === null || result.status > 1) {
      return { supported: false };
    }

    const help = (result.stdout ?? '') + (result.stderr ?? '');
    // The extension passes --ecosystem and --format json. Both must exist.
    return {
      supported: help.includes('--ecosystem') && help.includes('--format'),
    };
  } catch {
    return { supported: false };
  }
}

/** Largest answer that the extension reads (a verdict document is a few KB). */
const MAX_VET_OUTPUT_BYTES = 1024 * 1024;

/**
 * Run `credenzo vet --format json --ecosystem <eco> [--online] -- <package>`.
 *
 * Resolves with the parsed verdict document (not checked: `adaptVerdict`
 * does that).
 *
 * Rejects with:
 *  - Error('VET_TIMEOUT') after VET_TIMEOUT_MS
 *  - Error message if exit code > 1 (hard error)
 *  - Parse error if stdout is not valid JSON
 */
export function runVet(
  binaryPath: string,
  pkg: LaunchPackage,
  options: VetOptions
): Promise<unknown> {
  return new Promise<unknown>((resolve, reject) => {
    const spawnImpl = options.spawnFn ?? cp.spawn;

    // Options first, then `--`: the package text comes from the open file and
    // must not be read as an option.
    const args = ['vet', '--format', 'json', '--ecosystem', pkg.ecosystem];
    if (options.online) args.push('--online');
    args.push('--', vetSpec(pkg));

    const proc = spawnImpl(binaryPath, args, { shell: false, windowsHide: true });

    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;

    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      proc.kill('SIGTERM');
      reject(new Error('VET_TIMEOUT'));
    }, VET_TIMEOUT_MS);

    proc.stdout?.on('data', (chunk: Buffer) => {
      if (done) return;
      size += chunk.length;
      if (size > MAX_VET_OUTPUT_BYTES) {
        done = true;
        clearTimeout(timer);
        proc.kill('SIGTERM');
        reject(new Error('credenzo vet printed more than 1 MB'));
        return;
      }
      chunks.push(chunk);
    });

    proc.on('error', (err: Error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      reject(err);
    });

    proc.on('close', (code: number | null) => {
      if (done) return;
      done = true;
      clearTimeout(timer);

      // Exit codes 0 and 1 both come with a verdict document. A process that
      // a signal stopped has no exit code and no complete answer.
      if (code === null || code > 1) {
        reject(new Error(`credenzo vet exited with code ${code}`));
        return;
      }

      try {
        // With --online the command can print one message before the
        // document ("Online fetch failed … using bundled registry"). The
        // document starts at the first line that is "{".
        const out = Buffer.concat(chunks).toString('utf8');
        const start = out.startsWith('{') ? 0 : out.search(/^\{\r?$/m);
        resolve(JSON.parse(start >= 0 ? out.slice(start) : out) as unknown);
      } catch {
        reject(new Error('credenzo vet did not print JSON'));
      }
    });
  });
}
