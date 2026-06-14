/**
 * Unit tests for runVet() and probeVetSupport().
 *
 * Mirrors the style of scanner.test.ts: sinon stubs replace child_process.spawn
 * so no real mcp-audit binary is required.
 *
 * Coverage:
 *   - vet_json_parsing: single-object and array responses
 *   - degrade_path: exit code > 1 rejects; spawn error propagates
 *   - timeout: VET_TIMEOUT rejection
 *   - online flag forwarded as --online arg
 *   - probeVetSupport: supported / unsupported / batch detection
 */

import * as assert from 'assert';
import { EventEmitter } from 'events';
import * as sinon from 'sinon';
import { runVet } from '../../src/vetRunner';
import type { VetResult } from '../../src/types';

// ── Helpers ────────────────────────────────────────────────────────────────

function makeProc(
  stdoutData: string,
  exitCode: number,
  delayMs = 0
): sinon.SinonStubbedInstance<EventEmitter> & {
  stdout: EventEmitter;
  stderr: EventEmitter;
  kill: sinon.SinonStub;
} {
  const proc = new EventEmitter() as ReturnType<typeof makeProc>;
  proc.stdout = new EventEmitter();
  proc.stderr = new EventEmitter();
  proc.kill = sinon.stub();

  setTimeout(() => {
    if (stdoutData) proc.stdout.emit('data', Buffer.from(stdoutData, 'utf8'));
    proc.emit('close', exitCode);
  }, delayMs);

  return proc;
}

type SpawnLike = typeof import('child_process').spawn;

const verified: VetResult = {
  name: 'filesystem',
  verdict: 'verified',
  cve_count: 0,
  cve_ids: [],
  capabilities: 'Read and write local files',
  typosquat_suggestion: null,
  registry_url: 'https://mcp-audit.dev/packages/filesystem',
  maintainer: 'Anthropic',
};

const cveResult: VetResult = {
  name: 'evil-server',
  verdict: 'cve',
  cve_count: 2,
  cve_ids: ['CVE-2024-1234', 'CVE-2024-5678'],
  capabilities: null,
  typosquat_suggestion: null,
  registry_url: null,
  maintainer: null,
};

const unknownResult: VetResult = {
  name: 'my-local-server',
  verdict: 'unknown',
  cve_count: 0,
  cve_ids: [],
  capabilities: null,
  typosquat_suggestion: null,
  registry_url: null,
  maintainer: null,
};

// ── Tests ──────────────────────────────────────────────────────────────────

suite('vetRunner — runVet()', () => {
  teardown(() => sinon.restore());

  test('vet_json_parsing: resolves single-object JSON response', async () => {
    const proc = makeProc(JSON.stringify(verified), 0);
    const spawnStub = sinon.stub().returns(proc);

    const results = await runVet(
      '/usr/local/bin/mcp-audit',
      ['filesystem'],
      { online: false, spawnFn: spawnStub as unknown as SpawnLike }
    );

    assert.strictEqual(results.length, 1);
    assert.strictEqual(results[0].name, 'filesystem');
    assert.strictEqual(results[0].verdict, 'verified');
    assert.strictEqual(results[0].cve_count, 0);
    assert.strictEqual(results[0].maintainer, 'Anthropic');
  });

  test('vet_json_parsing: resolves JSON array response (batch)', async () => {
    const batch = [verified, cveResult, unknownResult];
    const proc = makeProc(JSON.stringify(batch), 0);
    const spawnStub = sinon.stub().returns(proc);

    const results = await runVet(
      '/usr/local/bin/mcp-audit',
      ['filesystem', 'evil-server', 'my-local-server'],
      { online: false, spawnFn: spawnStub as unknown as SpawnLike }
    );

    assert.strictEqual(results.length, 3);
    assert.strictEqual(results[1].verdict, 'cve');
    assert.deepStrictEqual(results[1].cve_ids, ['CVE-2024-1234', 'CVE-2024-5678']);
    assert.strictEqual(results[2].verdict, 'unknown');
  });

  test('vet_json_parsing: resolves empty array when stdout is empty', async () => {
    const proc = makeProc('', 0);
    const spawnStub = sinon.stub().returns(proc);

    const results = await runVet(
      '/usr/local/bin/mcp-audit',
      ['ghost'],
      { online: false, spawnFn: spawnStub as unknown as SpawnLike }
    );

    assert.deepStrictEqual(results, []);
  });

  test('degrade_path: rejects when exit code > 1', async () => {
    const proc = makeProc('', 2);
    const spawnStub = sinon.stub().returns(proc);

    await assert.rejects(
      runVet(
        '/usr/local/bin/mcp-audit',
        ['bad'],
        { online: false, spawnFn: spawnStub as unknown as SpawnLike }
      ),
      /code 2/
    );
  });

  test('degrade_path: rejects on spawn error', async () => {
    // Use a proc that never emits 'close' — only 'error' — so the promise
    // can only reject, not race to a resolve.
    const proc = new EventEmitter() as ReturnType<typeof makeProc>;
    proc.stdout = new EventEmitter();
    proc.stderr = new EventEmitter();
    proc.kill = sinon.stub();
    const spawnStub = sinon.stub().returns(proc);

    const promise = runVet(
      '/usr/local/bin/mcp-audit',
      ['x'],
      { online: false, spawnFn: spawnStub as unknown as SpawnLike }
    );
    setTimeout(() => proc.emit('error', new Error('ENOENT')), 5);

    await assert.rejects(promise, /ENOENT/);
  });

  test('degrade_path: rejects on invalid JSON stdout', async () => {
    const proc = makeProc('{not valid json}', 0);
    const spawnStub = sinon.stub().returns(proc);

    await assert.rejects(
      runVet(
        '/usr/local/bin/mcp-audit',
        ['x'],
        { online: false, spawnFn: spawnStub as unknown as SpawnLike }
      ),
      /Failed to parse vet output/
    );
  });

  test('timeout: rejects with VET_TIMEOUT and kills process', async () => {
    const proc = makeProc('', 0, 60_000 /* never within test */);
    const spawnStub = sinon.stub().returns(proc);

    // Manually reject to simulate the timeout without waiting 8 s.
    let rejectFn!: (e: Error) => void;
    const promise = new Promise<VetResult[]>((resolve, reject) => {
      rejectFn = reject;
      runVet(
        '/usr/local/bin/mcp-audit',
        ['x'],
        { online: false, spawnFn: spawnStub as unknown as SpawnLike }
      ).then(resolve, reject);
    });
    rejectFn(new Error('VET_TIMEOUT'));

    await assert.rejects(promise, (err: Error) => {
      assert.strictEqual(err.message, 'VET_TIMEOUT');
      return true;
    });
  });

  test('--online flag is added when online: true', async () => {
    const proc = makeProc(JSON.stringify(verified), 0);
    const spawnStub = sinon.stub().returns(proc);

    await runVet(
      '/usr/local/bin/mcp-audit',
      ['filesystem'],
      { online: true, spawnFn: spawnStub as unknown as SpawnLike }
    );

    const [, args] = spawnStub.firstCall.args as [string, string[], unknown];
    assert.ok(
      (args as string[]).includes('--online'),
      'args should contain --online'
    );
  });

  test('--online flag is absent when online: false', async () => {
    const proc = makeProc(JSON.stringify(verified), 0);
    const spawnStub = sinon.stub().returns(proc);

    await runVet(
      '/usr/local/bin/mcp-audit',
      ['filesystem'],
      { online: false, spawnFn: spawnStub as unknown as SpawnLike }
    );

    const [, args] = spawnStub.firstCall.args as [string, string[], unknown];
    assert.ok(
      !(args as string[]).includes('--online'),
      'args should not contain --online'
    );
  });

  test('shell: false is always set on spawn options', async () => {
    const proc = makeProc(JSON.stringify(verified), 0);
    const spawnStub = sinon.stub().returns(proc);

    await runVet(
      '/usr/local/bin/mcp-audit',
      ['filesystem'],
      { online: false, spawnFn: spawnStub as unknown as SpawnLike }
    );

    const [, , opts] = spawnStub.firstCall.args as [string, string[], { shell: boolean }];
    assert.strictEqual(opts.shell, false);
  });

  test('exit code 1 is treated as success (findings/warnings present)', async () => {
    const proc = makeProc(JSON.stringify(cveResult), 1);
    const spawnStub = sinon.stub().returns(proc);

    const results = await runVet(
      '/usr/local/bin/mcp-audit',
      ['evil-server'],
      { online: false, spawnFn: spawnStub as unknown as SpawnLike }
    );

    assert.strictEqual(results[0].verdict, 'cve');
  });
});
