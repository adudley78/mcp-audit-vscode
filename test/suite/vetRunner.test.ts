/**
 * Unit tests for runVet(). A stub replaces child_process.spawn, so no binary
 * is needed. scripts/contract-test.mjs runs runVet() against the real command.
 */

import * as assert from 'assert';
import { EventEmitter } from 'events';
import * as sinon from 'sinon';
import { runVet } from '../../src/vetRunner';
import type { LaunchPackage } from '../../src/launchPackage';

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

const PKG: LaunchPackage = { ecosystem: 'npm', name: 'mcp-remote', version: null };
const DOC = JSON.stringify({ schema_version: '1.0.0', package: { name: 'mcp-remote' } });

function spawnStub(stdout: string, code: number | null, delayMs = 0): sinon.SinonStub {
  return sinon.stub().callsFake(() => {
    const proc = makeProc(stdout, code as number, delayMs);
    return proc;
  });
}

suite('vetRunner — runVet()', () => {
  teardown(() => sinon.restore());

  test('resolves with the parsed document on exit code 0', async () => {
    const spawn = spawnStub(DOC, 0);
    const doc = await runVet('credenzo', PKG, { online: false, spawnFn: spawn as unknown as SpawnLike });
    assert.deepStrictEqual(doc, JSON.parse(DOC));
  });

  test('exit code 1 comes with a document too', async () => {
    const spawn = spawnStub(DOC, 1);
    const doc = await runVet('credenzo', PKG, { online: false, spawnFn: spawn as unknown as SpawnLike });
    assert.deepStrictEqual(doc, JSON.parse(DOC));
  });

  test('the arguments: options first, the ecosystem, then -- and one package', async () => {
    const spawn = spawnStub(DOC, 0);
    await runVet(
      '/bin/credenzo',
      { ecosystem: 'pypi', name: 'mcp-server-fetch', version: '1.2.3' },
      { online: false, spawnFn: spawn as unknown as SpawnLike }
    );
    assert.strictEqual(spawn.firstCall.args[0], '/bin/credenzo');
    assert.deepStrictEqual(spawn.firstCall.args[1], [
      'vet', '--format', 'json', '--ecosystem', 'pypi', '--', 'mcp-server-fetch==1.2.3',
    ]);
    assert.strictEqual(spawn.firstCall.args[2].shell, false);
  });

  test('--online is before --, and only when it is on', async () => {
    const spawn = spawnStub(DOC, 0);
    await runVet('credenzo', PKG, { online: true, spawnFn: spawn as unknown as SpawnLike });
    const args = spawn.firstCall.args[1] as string[];
    assert.ok(args.indexOf('--online') > 0 && args.indexOf('--online') < args.indexOf('--'));
    assert.strictEqual(args[args.length - 1], 'mcp-remote');
  });

  test('rejects when the exit code is 2', async () => {
    const spawn = spawnStub('', 2);
    await assert.rejects(
      runVet('credenzo', PKG, { online: false, spawnFn: spawn as unknown as SpawnLike }),
      /exited with code 2/
    );
  });

  test('rejects when a signal stopped the process (no exit code)', async () => {
    const spawn = spawnStub(DOC.slice(0, 10), null);
    await assert.rejects(
      runVet('credenzo', PKG, { online: false, spawnFn: spawn as unknown as SpawnLike }),
      /exited with code null/
    );
  });

  test('rejects when stdout is empty or is not JSON, and does not repeat the output', async () => {
    for (const out of ['', 'Traceback secret-text']) {
      const spawn = spawnStub(out, 0);
      await assert.rejects(
        runVet('credenzo', PKG, { online: false, spawnFn: spawn as unknown as SpawnLike }),
        (err: Error) => err.message === 'credenzo vet did not print JSON'
      );
    }
  });

  test('rejects on a spawn error', async () => {
    const spawn = sinon.stub().callsFake(() => {
      const proc = makeProc('', 0, 50);
      setTimeout(() => proc.emit('error', new Error('ENOENT')), 0);
      return proc;
    });
    await assert.rejects(
      runVet('credenzo', PKG, { online: false, spawnFn: spawn as unknown as SpawnLike }),
      /ENOENT/
    );
  });

  test('a character that two chunks share is read correctly', async () => {
    const text = JSON.stringify({ schema_version: '1.0.0', note: '0.1.32–0.1.38' });
    const bytes = Buffer.from(text, 'utf8');
    const cut = bytes.indexOf(0xe2) + 1; // inside the 3 bytes of the dash
    const spawn = sinon.stub().callsFake(() => {
      const proc = makeProc('', 0, 20);
      setTimeout(() => {
        proc.stdout.emit('data', bytes.subarray(0, cut));
        proc.stdout.emit('data', bytes.subarray(cut));
      }, 0);
      return proc;
    });
    const doc = (await runVet('credenzo', PKG, {
      online: false,
      spawnFn: spawn as unknown as SpawnLike,
    })) as { note: string };
    assert.strictEqual(doc.note, '0.1.32–0.1.38');
  });

  test('more than 1 MB of output stops the process and rejects', async () => {
    let proc: ReturnType<typeof makeProc> | undefined;
    const spawn = sinon.stub().callsFake(() => {
      proc = makeProc('', 0, 200);
      const p = proc;
      setTimeout(() => {
        p.stdout.emit('data', Buffer.alloc(700 * 1024, 0x20));
        p.stdout.emit('data', Buffer.alloc(700 * 1024, 0x20));
      }, 0);
      return proc;
    });
    await assert.rejects(
      runVet('credenzo', PKG, { online: false, spawnFn: spawn as unknown as SpawnLike }),
      /more than 1 MB/
    );
    assert.ok(proc);
    sinon.assert.calledOnce(proc.kill);
  });

  test('timeout: rejects with VET_TIMEOUT and stops the process', async function () {
    this.timeout(12_000);
    let proc: ReturnType<typeof makeProc> | undefined;
    const spawn = sinon.stub().callsFake(() => {
      proc = makeProc(DOC, 0, 60_000);
      return proc;
    });
    await assert.rejects(
      runVet('credenzo', PKG, { online: false, spawnFn: spawn as unknown as SpawnLike }),
      /VET_TIMEOUT/
    );
    assert.ok(proc);
    sinon.assert.calledOnce(proc.kill);
  });
});
