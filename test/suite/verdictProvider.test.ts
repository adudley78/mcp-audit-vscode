/**
 * Unit / integration tests for the VerdictProvider and its pure helpers.
 *
 * Coverage:
 *   - vet_json_parsing: formatBadge maps every verdict type correctly
 *   - decoration_mapping: buildDecorationOptions produces correct after-text
 *   - unknown_path: 'unknown' verdict emits no diagnostic
 *   - degrade_path: supported=false → runVet never called
 *   - degrade_path: binary missing → runVet never called
 *   - debounce_cache: rapid triggers → runVet called once per unique server
 *   - cache: second trigger with same server → runVet not called again
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import * as sinon from 'sinon';
import {
  formatBadge,
  formatHover,
  buildDecorationOptions,
  VerdictProvider,
} from '../../src/verdictProvider';
import type { VetResult } from '../../src/types';
import type { VetOptions } from '../../src/vetRunner';

// ── Fixtures ───────────────────────────────────────────────────────────────

function makeResult(overrides: Partial<VetResult> = {}): VetResult {
  return {
    name: 'filesystem',
    verdict: 'verified',
    cve_count: 0,
    cve_ids: [],
    capabilities: 'Read and write local files',
    typosquat_suggestion: null,
    registry_url: 'https://mcp-audit.dev/packages/filesystem',
    maintainer: 'Anthropic',
    ...overrides,
  };
}

async function makeDoc(content: string): Promise<vscode.TextDocument> {
  return vscode.workspace.openTextDocument({ content, language: 'json' });
}

// ── formatBadge ────────────────────────────────────────────────────────────

suite('verdictProvider — formatBadge()', () => {
  test('decoration_mapping: verified with 0 CVEs shows checkmark', () => {
    const badge = formatBadge(makeResult());
    assert.ok(badge.text.includes('✓ verified'), `text: ${badge.text}`);
    assert.ok(badge.text.includes('0 known CVEs'), `text: ${badge.text}`);
    assert.ok(badge.text.includes('Anthropic'), `text: ${badge.text}`);
  });

  test('decoration_mapping: verified without maintainer omits parenthetical', () => {
    const badge = formatBadge(makeResult({ maintainer: null }));
    assert.ok(badge.text.includes('✓ verified'));
    assert.ok(!badge.text.includes('('), `should not have parens: ${badge.text}`);
  });

  test('vet_json_parsing: cve verdict shows warning and CVE IDs', () => {
    const badge = formatBadge(
      makeResult({
        verdict: 'cve',
        cve_count: 2,
        cve_ids: ['CVE-2024-1111', 'CVE-2024-2222'],
      })
    );
    assert.ok(badge.text.includes('⚠'), `text: ${badge.text}`);
    assert.ok(badge.text.includes('2 known CVEs'), `text: ${badge.text}`);
    assert.ok(badge.text.includes('CVE-2024-1111'), `text: ${badge.text}`);
  });

  test('vet_json_parsing: cve with singular count uses singular form', () => {
    const badge = formatBadge(
      makeResult({ verdict: 'cve', cve_count: 1, cve_ids: ['CVE-2024-9999'] })
    );
    assert.ok(badge.text.includes('1 known CVE'), `text: ${badge.text}`);
    assert.ok(!badge.text.includes('CVEs'), `text: ${badge.text}`);
  });

  test('decoration_mapping: typosquat shows warning and suggestion', () => {
    const badge = formatBadge(
      makeResult({
        verdict: 'typosquat',
        typosquat_suggestion: 'real-filesystem',
      })
    );
    assert.ok(badge.text.includes('⚠'), `text: ${badge.text}`);
    assert.ok(badge.text.includes('typosquat'), `text: ${badge.text}`);
    assert.ok(badge.text.includes('real-filesystem'), `text: ${badge.text}`);
  });

  test('unknown_path: unknown verdict shows question mark, no ⚠', () => {
    const badge = formatBadge(makeResult({ verdict: 'unknown' }));
    assert.ok(badge.text.includes('?'), `text: ${badge.text}`);
    assert.ok(!badge.text.includes('⚠'), `text: ${badge.text}`);
    assert.ok(!badge.text.includes('✓'), `text: ${badge.text}`);
  });
});

// ── formatHover ────────────────────────────────────────────────────────────

suite('verdictProvider — formatHover()', () => {
  test('verified hover includes capabilities and registry link', () => {
    const md = formatHover(makeResult());
    const value = md.value;
    assert.ok(value.includes('✓ verified'), value);
    assert.ok(value.includes('Capabilities:'), value);
    assert.ok(value.includes('mcp-audit.dev'), value);
  });

  test('cve hover includes CVE IDs', () => {
    const md = formatHover(
      makeResult({
        verdict: 'cve',
        cve_count: 1,
        cve_ids: ['CVE-2024-4242'],
      })
    );
    assert.ok(md.value.includes('CVE-2024-4242'), md.value);
  });

  test('unknown hover says "Not in registry"', () => {
    const md = formatHover(makeResult({ verdict: 'unknown', capabilities: null, registry_url: null }));
    assert.ok(md.value.includes('Not in registry'), md.value);
    assert.ok(!md.value.includes('Capabilities:'), md.value);
    assert.ok(!md.value.includes('mcp-audit.dev'), md.value);
  });

  test('typosquat hover shows suggestion as inline code', () => {
    const md = formatHover(
      makeResult({ verdict: 'typosquat', typosquat_suggestion: 'correct-pkg' })
    );
    assert.ok(md.value.includes('`correct-pkg`'), md.value);
  });
});

// ── buildDecorationOptions ─────────────────────────────────────────────────

suite('verdictProvider — buildDecorationOptions()', () => {
  test('decoration_mapping: returns one option per cached server', async () => {
    const doc = await makeDoc(
      JSON.stringify({
        mcpServers: {
          filesystem: { command: 'node', args: [] },
          fetch: { command: 'uvx', args: [] },
        },
      })
    );
    const range = doc.lineAt(0).range;
    const servers = [
      { name: 'filesystem', range },
      { name: 'fetch', range },
      { name: 'uncached-server', range },
    ];
    const cache = new Map<string, VetResult>([
      ['filesystem', makeResult()],
      ['fetch', makeResult({ name: 'fetch', verdict: 'unknown' })],
    ]);

    const opts = buildDecorationOptions(servers, cache);

    assert.strictEqual(opts.length, 2, 'uncached server should be skipped');
    assert.ok(opts[0].renderOptions?.after?.contentText?.includes('✓'), 'first opt: verified');
    assert.ok(opts[1].renderOptions?.after?.contentText?.includes('?'), 'second opt: unknown');
  });

  test('decoration_mapping: empty cache produces empty array', () => {
    const range = new vscode.Range(0, 0, 0, 10);
    const opts = buildDecorationOptions(
      [{ name: 'x', range }],
      new Map()
    );
    assert.strictEqual(opts.length, 0);
  });
});

// ── VerdictProvider class ──────────────────────────────────────────────────

suite('verdictProvider — VerdictProvider', () => {
  let provider: VerdictProvider;

  teardown(() => {
    provider?.dispose();
    sinon.restore();
  });

  test('degrade_path: runVet never called when binary is missing', async () => {
    const runVetSpy = sinon.stub().resolves([]);
    const probeSpy = sinon
      .stub()
      .returns({ supported: true, supportsBatch: false });

    provider = new VerdictProvider(() => { /* noop */ }, {
      runVet: runVetSpy as unknown as (b: string, n: string[], o: VetOptions) => Promise<VetResult[]>,
      probeVetSupport: probeSpy,
      locateBinary: () => undefined, // binary missing
    });

    const doc = await makeDoc(
      JSON.stringify({ mcpServers: { filesystem: { command: 'node' } } })
    );
    provider.trigger(doc);
    // Wait long enough for debounce to fire.
    await new Promise<void>((r) => setTimeout(r, 500));

    sinon.assert.notCalled(runVetSpy);
  });

  test('degrade_path: runVet never called when vet is unsupported', async () => {
    const runVetSpy = sinon.stub().resolves([]);

    provider = new VerdictProvider(() => { /* noop */ }, {
      runVet: runVetSpy as unknown as (b: string, n: string[], o: VetOptions) => Promise<VetResult[]>,
      probeVetSupport: () => ({ supported: false, supportsBatch: false }),
      locateBinary: () => '/usr/local/bin/mcp-audit',
    });

    const doc = await makeDoc(
      JSON.stringify({ mcpServers: { filesystem: { command: 'node' } } })
    );
    provider.trigger(doc);
    await new Promise<void>((r) => setTimeout(r, 500));

    sinon.assert.notCalled(runVetSpy);
  });

  test('debounce_cache: rapid triggers result in a single runVet call', async () => {
    let callCount = 0;
    const runVetFake = async (_b: string, names: string[], _o: VetOptions) => {
      callCount++;
      return names.map((n) => makeResult({ name: n }));
    };

    provider = new VerdictProvider(() => { /* noop */ }, {
      runVet: runVetFake,
      probeVetSupport: () => ({ supported: true, supportsBatch: true }),
      locateBinary: () => '/usr/local/bin/mcp-audit',
    });

    const doc = await makeDoc(
      JSON.stringify({ mcpServers: { filesystem: { command: 'node' } } })
    );

    // Fire trigger 5 times in quick succession.
    for (let i = 0; i < 5; i++) provider.trigger(doc);

    await new Promise<void>((r) => setTimeout(r, 500));

    assert.strictEqual(callCount, 1, 'debounce should collapse to a single call');
  });

  test('cache: second trigger for same server does not call runVet again', async () => {
    let callCount = 0;
    const runVetFake = async (_b: string, names: string[], _o: VetOptions) => {
      callCount++;
      return names.map((n) => makeResult({ name: n }));
    };

    provider = new VerdictProvider(() => { /* noop */ }, {
      runVet: runVetFake,
      probeVetSupport: () => ({ supported: true, supportsBatch: false }),
      locateBinary: () => '/usr/local/bin/mcp-audit',
    });

    const doc = await makeDoc(
      JSON.stringify({ mcpServers: { filesystem: { command: 'node' } } })
    );

    // First trigger — populates cache.
    provider.trigger(doc);
    await new Promise<void>((r) => setTimeout(r, 500));
    assert.strictEqual(callCount, 1, 'first trigger should call runVet once');

    // Second trigger — server is cached, runVet should not fire again.
    provider.trigger(doc);
    await new Promise<void>((r) => setTimeout(r, 500));
    assert.strictEqual(callCount, 1, 'second trigger should use cache');
  });

  test('unknown_path: unknown verdict does not produce a diagnostic', async () => {
    const runVetFake = async (_b: string, names: string[], _o: VetOptions) =>
      names.map((n) =>
        makeResult({ name: n, verdict: 'unknown', capabilities: null, registry_url: null })
      );

    provider = new VerdictProvider(() => { /* noop */ }, {
      runVet: runVetFake,
      probeVetSupport: () => ({ supported: true, supportsBatch: false }),
      locateBinary: () => '/usr/local/bin/mcp-audit',
    });

    const doc = await makeDoc(
      JSON.stringify({ mcpServers: { 'my-local-tool': { command: 'node' } } })
    );
    provider.trigger(doc);
    await new Promise<void>((r) => setTimeout(r, 500));

    // No diagnostic should be registered for the 'unknown' verdict.
    const diags = vscode.languages.getDiagnostics(doc.uri);
    const vetDiags = diags.filter((d) => d.source === 'mcp-audit-vet');
    assert.strictEqual(
      vetDiags.length,
      0,
      'unknown verdict must not produce a diagnostic squiggle'
    );
  });

  test('vet_json_parsing: cve verdict produces a Warning diagnostic', async () => {
    const runVetFake = async (_b: string, names: string[], _o: VetOptions) =>
      names.map((n) =>
        makeResult({
          name: n,
          verdict: 'cve',
          cve_count: 1,
          cve_ids: ['CVE-2024-9001'],
        })
      );

    provider = new VerdictProvider(() => { /* noop */ }, {
      runVet: runVetFake,
      probeVetSupport: () => ({ supported: true, supportsBatch: false }),
      locateBinary: () => '/usr/local/bin/mcp-audit',
    });

    const doc = await makeDoc(
      JSON.stringify({ mcpServers: { vuln: { command: 'node' } } })
    );
    provider.trigger(doc);
    await new Promise<void>((r) => setTimeout(r, 500));

    const diags = vscode.languages.getDiagnostics(doc.uri);
    const vetDiags = diags.filter((d) => d.source === 'mcp-audit-vet');
    assert.strictEqual(vetDiags.length, 1, 'one Warning for the CVE');
    assert.strictEqual(vetDiags[0].severity, vscode.DiagnosticSeverity.Warning);
    assert.ok(vetDiags[0].message.includes('CVE-2024-9001'), vetDiags[0].message);
  });

  test('vet_json_parsing: typosquat verdict produces a Warning diagnostic', async () => {
    const runVetFake = async (_b: string, names: string[], _o: VetOptions) =>
      names.map((n) =>
        makeResult({
          name: n,
          verdict: 'typosquat',
          typosquat_suggestion: 'real-filesystem',
        })
      );

    provider = new VerdictProvider(() => { /* noop */ }, {
      runVet: runVetFake,
      probeVetSupport: () => ({ supported: true, supportsBatch: false }),
      locateBinary: () => '/usr/local/bin/mcp-audit',
    });

    const doc = await makeDoc(
      JSON.stringify({ mcpServers: { 'filesystemm': { command: 'node' } } })
    );
    provider.trigger(doc);
    await new Promise<void>((r) => setTimeout(r, 500));

    const diags = vscode.languages.getDiagnostics(doc.uri);
    const vetDiags = diags.filter((d) => d.source === 'mcp-audit-vet');
    assert.strictEqual(vetDiags.length, 1);
    assert.strictEqual(vetDiags[0].severity, vscode.DiagnosticSeverity.Warning);
    assert.ok(
      vetDiags[0].message.includes('real-filesystem'),
      vetDiags[0].message
    );
  });

  test('degrade_path: runVet error is swallowed and no crash occurs', async () => {
    const runVetFake = async () => {
      throw new Error('network error');
    };

    provider = new VerdictProvider(() => { /* noop */ }, {
      runVet: runVetFake,
      probeVetSupport: () => ({ supported: true, supportsBatch: true }),
      locateBinary: () => '/usr/local/bin/mcp-audit',
    });

    const doc = await makeDoc(
      JSON.stringify({ mcpServers: { x: { command: 'node' } } })
    );

    // Should not throw.
    provider.trigger(doc);
    await new Promise<void>((r) => setTimeout(r, 500));

    // No diagnostics (vet failed, nothing to show).
    const diags = vscode.languages.getDiagnostics(doc.uri);
    const vetDiags = diags.filter((d) => d.source === 'mcp-audit-vet');
    assert.strictEqual(vetDiags.length, 0);
  });

  test('clear(): removes diagnostics for the given URI', async () => {
    const runVetFake = async (_b: string, names: string[], _o: VetOptions) =>
      names.map((n) =>
        makeResult({ name: n, verdict: 'cve', cve_count: 1, cve_ids: ['CVE-2024-0000'] })
      );

    provider = new VerdictProvider(() => { /* noop */ }, {
      runVet: runVetFake,
      probeVetSupport: () => ({ supported: true, supportsBatch: false }),
      locateBinary: () => '/usr/local/bin/mcp-audit',
    });

    const doc = await makeDoc(
      JSON.stringify({ mcpServers: { x: { command: 'node' } } })
    );
    provider.trigger(doc);
    await new Promise<void>((r) => setTimeout(r, 500));

    // Verify the diagnostic was set.
    const before = vscode.languages.getDiagnostics(doc.uri).filter(
      (d) => d.source === 'mcp-audit-vet'
    );
    assert.strictEqual(before.length, 1, 'diagnostic should be set before clear');

    provider.clear(doc.uri);

    const after = vscode.languages.getDiagnostics(doc.uri).filter(
      (d) => d.source === 'mcp-audit-vet'
    );
    assert.strictEqual(after.length, 0, 'diagnostic should be cleared');
  });
});
