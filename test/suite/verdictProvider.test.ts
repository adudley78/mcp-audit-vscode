/**
 * Tests for the VerdictProvider and its formatting helpers.
 *
 * The provider tests give the provider the saved real answers of
 * `credenzo vet --format json` (test/fixtures/vet, made by
 * scripts/make-vet-fixtures.sh), so they see the form that the real command
 * prints. scripts/contract-test.mjs runs the same path against the installed
 * command.
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import * as sinon from 'sinon';
import {
  formatBadge,
  formatHover,
  cveLabel,
  fixedLabel,
  maliciousText,
  possibleText,
  escapeMarkdown,
  isPlainHttpsUrl,
  isRegistryUrl,
  buildDecorationOptions,
  VerdictProvider,
} from '../../src/verdictProvider';
import type { LaunchPackage } from '../../src/launchPackage';
import type { VetResult } from '../../src/types';
import type { VetOptions } from '../../src/vetRunner';

// ── Fixtures ───────────────────────────────────────────────────────────────

const FIXTURES = path.resolve(__dirname, '../../../test/fixtures/vet');

function fixture(name: string): unknown {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, `${name}.json`), 'utf8'));
}

/** The saved answer for each package that a test config starts. */
const ANSWERS: Record<string, string> = {
  'npm:@modelcontextprotocol/server-filesystem': 'verified-unpinned',
  'pypi:mcp-server-fetch': 'verified-pypi',
  'npm:mcp-remote@0.1.30': 'cve-pinned',
  'npm:mcp-remote': 'cve-unpinned',
  'npm:@modelcontextprotocol/server-filesytem': 'typosquat',
  'npm:not-a-real-pkg-zz': 'unknown',
  'pypi:claude-lite': 'malicious-other',
  'pypi:litellm==1.82.7': 'malicious-pinned',
  'pypi:litellm==1.83.0': 'malicious-not-this',
  'npm:@modelcontextprotocol/server-github': 'archived',
};

function makeResult(overrides: Partial<VetResult> = {}): VetResult {
  return {
    name: '@modelcontextprotocol/server-filesystem',
    verdict: 'verified',
    cve_count: 0,
    unchecked_cve_count: 0,
    cve_ids: [],
    fixed_cve_count: 0,
    possible_malicious_ids: [],
    other_malicious_ids: [],
    archived: false,
    successor: null,
    pinned: false,
    capabilities: 'file read, file write',
    typosquat_suggestion: null,
    registry_url: 'https://credenzo.io/servers/npm/x/',
    maintainer: 'Anthropic',
    ...overrides,
  };
}

async function makeDoc(content: string): Promise<vscode.TextDocument> {
  return vscode.workspace.openTextDocument({ content, language: 'json' });
}

function config(servers: Record<string, unknown>): string {
  return JSON.stringify({ mcpServers: servers }, null, 2);
}

const wait = (ms = 500): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** A fake `runVet` that answers from the saved files and records its calls. */
function fakeVet(): {
  calls: LaunchPackage[];
  run: (b: string, pkg: LaunchPackage, o: VetOptions) => Promise<unknown>;
} {
  const calls: LaunchPackage[] = [];
  return {
    calls,
    run: async (_b, pkg) => {
      calls.push(pkg);
      const spec =
        pkg.version === null
          ? pkg.name
          : pkg.ecosystem === 'npm'
            ? `${pkg.name}@${pkg.version}`
            : `${pkg.name}==${pkg.version}`;
      const name = ANSWERS[`${pkg.ecosystem}:${spec}`];
      if (!name) throw new Error(`no saved answer for ${spec}`);
      return fixture(name);
    },
  };
}

function makeProvider(
  run: (b: string, pkg: LaunchPackage, o: VetOptions) => Promise<unknown>,
  log: (m: string) => void = () => { /* noop */ }
): VerdictProvider {
  return new VerdictProvider(log, {
    runVet: run,
    probeVetSupport: () => ({ supported: true }),
    locateBinary: () => '/usr/local/bin/credenzo',
  });
}

function verdictDiagnostics(doc: vscode.TextDocument): vscode.Diagnostic[] {
  return vscode.languages
    .getDiagnostics(doc.uri)
    .filter((d) => d.source === 'credenzo-vet');
}

// ── formatBadge ────────────────────────────────────────────────────────────

suite('verdictProvider — formatBadge()', () => {
  test('verified with no CVE shows the check mark and the maintainer', () => {
    const badge = formatBadge(makeResult());
    assert.ok(badge.text.includes('✓ verified'), badge.text);
    assert.ok(badge.text.includes('0 known CVEs'), badge.text);
    assert.ok(badge.text.includes('Anthropic'), badge.text);
  });

  test('verified without maintainer has no parentheses', () => {
    const badge = formatBadge(makeResult({ maintainer: null }));
    assert.ok(!badge.text.includes('('), badge.text);
  });

  test('a long maintainer text is cut', () => {
    const badge = formatBadge(makeResult({ maintainer: 'x'.repeat(100) }));
    assert.ok(badge.text.length < 100, badge.text);
    assert.ok(badge.text.includes('…'), badge.text);
  });

  test('fixed CVEs of a package with no pin are not called fixed for the user', () => {
    assert.strictEqual(
      fixedLabel(makeResult({ fixed_cve_count: 2 })),
      '2 recorded CVEs, fixed in a later release'
    );
    assert.strictEqual(
      fixedLabel(makeResult({ fixed_cve_count: 1, pinned: true })),
      '1 recorded CVE, fixed in or before this version'
    );
  });

  test('cve label: no pin, pin, and a version that could not be compared', () => {
    assert.strictEqual(
      cveLabel(makeResult({ verdict: 'cve', cve_count: 1 })),
      '1 known CVE with no fix recorded'
    );
    assert.strictEqual(
      cveLabel(makeResult({ verdict: 'cve', cve_count: 2, pinned: true })),
      '2 known CVEs affect this version'
    );
    assert.strictEqual(
      cveLabel(makeResult({ verdict: 'cve', cve_count: 1, pinned: true })),
      '1 known CVE affects this version'
    );
    assert.strictEqual(
      cveLabel(makeResult({ verdict: 'cve', unchecked_cve_count: 1, pinned: true })),
      '1 known CVE: the version could not be compared'
    );
  });

  test('cve badge shows the warning sign and at most three IDs', () => {
    const badge = formatBadge(
      makeResult({
        verdict: 'cve',
        cve_count: 4,
        pinned: true,
        cve_ids: ['CVE-2024-1', 'CVE-2024-2', 'CVE-2024-3', 'CVE-2024-4'],
      })
    );
    assert.ok(badge.text.includes('⚠ 4 known CVEs affect this version'), badge.text);
    assert.ok(badge.text.includes('CVE-2024-3'), badge.text);
    assert.ok(!badge.text.includes('CVE-2024-4'), badge.text);
  });

  test('malicious badge shows the record ID', () => {
    const badge = formatBadge(makeResult({ verdict: 'malicious', cve_ids: ['MAL-2026-1'] }));
    assert.ok(badge.text.includes('✖ malicious package record — MAL-2026-1'), badge.text);
  });

  test('a MAL record that is not the verdict is a note after the verdict', () => {
    const possible = formatBadge(
      makeResult({ verdict: 'cve', cve_count: 1, possible_malicious_ids: ['MAL-2026-1'] })
    );
    assert.ok(possible.text.includes('⚠ 1 known CVE'), possible.text);
    assert.ok(possible.text.endsWith('· ⚠ malicious releases on record'), possible.text);
    assert.ok(!possible.text.includes('✖'), possible.text);
    const other = formatBadge(makeResult({ other_malicious_ids: ['MAL-2026-1'] }));
    assert.ok(other.text.endsWith('· malicious record for other releases'), other.text);
  });

  test('the sentences about a MAL record claim only what the record says', () => {
    assert.ok(maliciousText(makeResult({ pinned: true })).includes('lists this version'));
    assert.ok(maliciousText(makeResult()).includes('with no end'));
    assert.ok(maliciousText(makeResult()).includes('pins no version'));
    assert.ok(!maliciousText(makeResult()).includes('newest'));
    assert.ok(possibleText(makeResult({ pinned: true })).includes('did not compare'));
    const noPin = possibleText(makeResult());
    assert.ok(noPin.includes('pins no version'), noPin);
    assert.ok(!noPin.includes('not the newest'), noPin);
  });

  test('archived badge is not the check mark, and names the successor', () => {
    const badge = formatBadge(
      makeResult({ verdict: 'archived', archived: true, successor: 'github/github-mcp-server' })
    );
    assert.ok(badge.text.includes('⚠ archived, not maintained'), badge.text);
    assert.ok(badge.text.includes('github/github-mcp-server'), badge.text);
    assert.ok(!badge.text.includes('✓'), badge.text);
  });

  test('typosquat badge shows the registry name', () => {
    const badge = formatBadge(
      makeResult({ verdict: 'typosquat', typosquat_suggestion: 'real-filesystem' })
    );
    assert.ok(badge.text.includes('⚠ possible typosquat'), badge.text);
    assert.ok(badge.text.includes('real-filesystem'), badge.text);
  });

  test('listed and not verified does not show the check mark', () => {
    const badge = formatBadge(makeResult({ verdict: 'listed' }));
    assert.ok(badge.text.includes('in registry, not verified'), badge.text);
    assert.ok(!badge.text.includes('✓'), badge.text);
  });

  test('unknown shows the question mark only', () => {
    const badge = formatBadge(makeResult({ verdict: 'unknown' }));
    assert.ok(badge.text.includes('?'), badge.text);
    assert.ok(!badge.text.includes('⚠'), badge.text);
    assert.ok(!badge.text.includes('✓'), badge.text);
  });
});

// ── formatHover ────────────────────────────────────────────────────────────

suite('verdictProvider — formatHover()', () => {
  test('verified hover includes capabilities and registry link', () => {
    const md = formatHover(makeResult());
    const value = md.value;
    assert.ok(value.includes('✓ verified'), value);
    assert.ok(value.includes('Capabilities:'), value);
    assert.ok(value.includes('(https://credenzo.io/servers/npm/x/)'), value);
    assert.ok(value.includes('Package:'), value);
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
    assert.ok(!md.value.includes('View the registry entry'), md.value);
  });

  test('hover is not trusted, so a command link can not run', () => {
    assert.strictEqual(formatHover(makeResult()).isTrusted, false);
  });

  test('registry text can not add a Markdown link, an image or HTML to the hover', () => {
    const md = formatHover(
      makeResult({
        maintainer: '[x](command:workbench.action.terminal.new)',
        capabilities: '![i](http://example.test/p.png) <b>x</b>',
      })
    );
    assert.ok(!md.value.includes('[x](command:'), md.value);
    assert.ok(!md.value.includes('![i]('), md.value);
    assert.ok(!md.value.includes('<b>'), md.value);
    assert.ok(md.value.includes('\\[x\\]\\(command:'), md.value);
  });

  test('typosquat suggestion can not leave its inline code', () => {
    const md = formatHover(
      makeResult({ verdict: 'typosquat', typosquat_suggestion: 'a` [x](command:y) `b' })
    );
    assert.ok(md.value.includes('`a [x](command:y) b`'), md.value);
  });

  test('a registry link that is not a plain https URL is left out', () => {
    for (const bad of [
      'command:workbench.action.terminal.new',
      'http://example.test/x',
      'https://example.test/x) [y](command:z',
      'javascript:alert(1)',
    ]) {
      const md = formatHover(makeResult({ registry_url: bad }));
      assert.ok(!md.value.includes('View the registry entry'), bad);
      assert.strictEqual(isPlainHttpsUrl(bad), false, bad);
    }
    assert.strictEqual(isPlainHttpsUrl('https://credenzo.io/servers/x/'), true);
  });

  test('a bare address in registry text is not left as a link source', () => {
    assert.strictEqual(
      escapeMarkdown('see https://evil.example/x and www.evil.example'),
      'see https:\\/\\/evil.example/x and www\\.evil.example'
    );
  });

  test('the hover links only to a Credenzo host', () => {
    for (const ok of [
      'https://credenzo.io/servers/x/',
      'https://mcp-audit.dev/v1/verdicts/npm/x.json',
    ]) {
      assert.strictEqual(isRegistryUrl(ok), true, ok);
    }
    for (const bad of [
      'https://evil.example/x',
      'https://credenzo.io.evil.example/x',
      'https://user@credenzo.io/x',
      'https://credenzo.io:8443/x',
      'http://credenzo.io/x',
    ]) {
      assert.strictEqual(isRegistryUrl(bad), false, bad);
      const md = formatHover(makeResult({ registry_url: bad }));
      assert.ok(!md.value.includes('View the registry entry'), bad);
    }
  });

  test('a count that is not a number is shown as 0', () => {
    const md = formatHover(
      makeResult({ verdict: 'cve', cve_count: '[x](command:y)' as unknown as number, cve_ids: [] })
    );
    assert.ok(!md.value.includes('command:y'), md.value);
    assert.ok(md.value.includes('0 known CVEs with no fix recorded'), md.value);
  });

  test('malicious hover gives the record ID and no link text from the data', () => {
    const md = formatHover(
      makeResult({ verdict: 'malicious', cve_ids: ['MAL-2026-2269'], registry_url: null })
    );
    assert.ok(md.value.includes('Malicious package record'), md.value);
    assert.ok(md.value.includes('MAL-2026-2269'), md.value);
  });

  test('archived and other-release notes are in the hover, escaped', () => {
    const md = formatHover(
      makeResult({
        verdict: 'cve',
        cve_count: 1,
        archived: true,
        successor: '[x](command:y)',
        other_malicious_ids: ['MAL-2026-1'],
        possible_malicious_ids: ['MAL-2026-2'],
      })
    );
    assert.ok(md.value.includes('*Archived:*'), md.value);
    assert.ok(!md.value.includes('[x](command:y)'), md.value);
    assert.ok(md.value.includes('MAL-2026-1'), md.value);
    assert.ok(md.value.includes('MAL-2026-2'), md.value);
    assert.ok(md.value.includes('pins no version'), md.value);
  });

  test('a package name can not add Markdown to the hover', () => {
    const md = formatHover(makeResult({ name: '[x](command:y)' }));
    assert.ok(!md.value.includes('[x](command:y)'), md.value);
  });

  test('escapeMarkdown keeps a CVE ID readable', () => {
    assert.strictEqual(escapeMarkdown('CVE-2024-4242'), 'CVE-2024-4242');
    assert.strictEqual(escapeMarkdown('a\nb'), 'a b');
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
  test('one option for each cached key; a key with no result is skipped', () => {
    const range = new vscode.Range(0, 0, 0, 10);
    const cache = new Map<string, VetResult>([
      ['npm:a', makeResult()],
      ['npm:b', makeResult({ verdict: 'unknown' })],
    ]);
    const opts = buildDecorationOptions(
      [
        { name: 'npm:a', range },
        { name: 'npm:b', range },
        { name: 'npm:c', range },
      ],
      cache
    );
    assert.strictEqual(opts.length, 2);
    assert.ok(opts[0].renderOptions?.after?.contentText?.includes('✓'));
    assert.ok(opts[1].renderOptions?.after?.contentText?.includes('?'));
  });

  test('empty cache gives no option', () => {
    const range = new vscode.Range(0, 0, 0, 10);
    assert.strictEqual(buildDecorationOptions([{ name: 'x', range }], new Map()).length, 0);
  });
});

// ── VerdictProvider class ──────────────────────────────────────────────────

suite('verdictProvider — VerdictProvider with saved real answers', () => {
  let provider: VerdictProvider;

  teardown(() => {
    provider?.dispose();
    sinon.restore();
  });

  test('the package of the launch command is looked up, not the server key', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(
      config({
        files: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
        fetch: { command: 'uvx', args: ['mcp-server-fetch'] },
      })
    );
    provider.trigger(doc);
    await wait();

    assert.deepStrictEqual(
      vet.calls.map((c) => `${c.ecosystem}:${c.name}`).sort(),
      ['npm:@modelcontextprotocol/server-filesystem', 'pypi:mcp-server-fetch']
    );
    assert.strictEqual(verdictDiagnostics(doc).length, 0);
  });

  test('a server with no package gets no lookup', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(
      config({
        local: { command: 'node', args: ['./server.js'] },
        remote: { url: 'https://example.test/mcp' },
        wrapped: { command: 'cmd', args: ['/c', 'npx', '-y', 'mcp-remote'] },
      })
    );
    provider.trigger(doc);
    await wait();
    assert.strictEqual(vet.calls.length, 0);
  });

  test('a pinned version with open CVEs gives one Warning that names the package', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(
      config({ proxy: { command: 'npx', args: ['-y', 'mcp-remote@0.1.30', 'https://example.test'] } })
    );
    provider.trigger(doc);
    await wait();

    assert.strictEqual(vet.calls[0].version, '0.1.30');
    const diags = verdictDiagnostics(doc);
    assert.strictEqual(diags.length, 1);
    assert.strictEqual(diags[0].severity, vscode.DiagnosticSeverity.Warning);
    assert.ok(diags[0].message.startsWith('mcp-remote: 6 known CVEs affect this version'), diags[0].message);
    assert.ok(!diags[0].message.includes('CVE-2025-6514'), 'the fixed CVE is not listed');
    // The Warning is on the server key.
    assert.strictEqual(doc.getText(diags[0].range), '"proxy"');
  });

  test('a typosquat gives one Warning with the registry name', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(
      config({ files: { command: 'npx', args: ['@modelcontextprotocol/server-filesytem'] } })
    );
    provider.trigger(doc);
    await wait();
    const diags = verdictDiagnostics(doc);
    assert.strictEqual(diags.length, 1);
    assert.strictEqual(diags[0].code, 'TYPOSQUAT');
    assert.ok(diags[0].message.includes('@modelcontextprotocol/server-filesystem'), diags[0].message);
  });

  test('a MAL record that names the pinned version gives one Error with the record ID', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(config({ llm: { command: 'uvx', args: ['litellm==1.82.7'] } }));
    provider.trigger(doc);
    await wait();
    const diags = verdictDiagnostics(doc);
    assert.strictEqual(diags.length, 1);
    assert.strictEqual(diags[0].severity, vscode.DiagnosticSeverity.Error);
    assert.strictEqual(diags[0].code, 'MAL-2026-2144');
    assert.ok(diags[0].message.includes('lists this version'), diags[0].message);
  });

  test('a MAL record for other releases: the CVE Warning stays, and the record is Information', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(config({ llm: { command: 'uvx', args: ['litellm==1.83.0'] } }));
    provider.trigger(doc);
    await wait();
    const diags = verdictDiagnostics(doc);
    assert.strictEqual(diags.length, 2);
    const warning = diags.find((d) => d.severity === vscode.DiagnosticSeverity.Warning);
    const info = diags.find((d) => d.severity === vscode.DiagnosticSeverity.Information);
    assert.ok(warning?.message.includes('17 known CVEs affect this version'), warning?.message);
    assert.ok(info?.message.includes('the pinned version is not one of them'), info?.message);
    assert.ok(!diags.some((d) => d.severity === vscode.DiagnosticSeverity.Error));
  });

  test('no pin, and a record that names releases: one Warning that makes no claim about the newest release', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(config({ lite: { command: 'uvx', args: ['claude-lite'] } }));
    provider.trigger(doc);
    await wait();
    const diags = verdictDiagnostics(doc);
    assert.strictEqual(diags.length, 1);
    assert.strictEqual(diags[0].severity, vscode.DiagnosticSeverity.Warning);
    assert.strictEqual(diags[0].code, 'MAL-2026-2269');
    assert.ok(diags[0].message.includes('pins no version'), diags[0].message);
  });

  test('an archived package gives one Information diagnostic', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(
      config({ gh: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] } })
    );
    provider.trigger(doc);
    await wait();
    const diags = verdictDiagnostics(doc);
    assert.strictEqual(diags.length, 1);
    assert.strictEqual(diags[0].code, 'ARCHIVED');
    assert.strictEqual(diags[0].severity, vscode.DiagnosticSeverity.Information);
    assert.ok(diags[0].message.includes('github/github-mcp-server'), diags[0].message);
  });

  test('an unknown package gives no diagnostic', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(config({ x: { command: 'npx', args: ['not-a-real-pkg-zz'] } }));
    provider.trigger(doc);
    await wait();
    assert.strictEqual(vet.calls.length, 1);
    assert.strictEqual(verdictDiagnostics(doc).length, 0);
  });

  test('two servers that start one package give one lookup; a second trigger gives none', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(
      config({
        a: { command: 'npx', args: ['mcp-remote', 'https://a.example.test'] },
        b: { command: 'npx', args: ['mcp-remote', 'https://b.example.test'] },
      })
    );
    for (let i = 0; i < 5; i++) provider.trigger(doc);
    await wait();
    assert.strictEqual(vet.calls.length, 1, 'debounce and one call for each package');
    assert.strictEqual(verdictDiagnostics(doc).length, 2, 'each server gets the Warning');

    provider.trigger(doc);
    await wait();
    assert.strictEqual(vet.calls.length, 1, 'the cache answers the second trigger');
  });

  test('one package that fails does not stop the others, and the log says so one time', async () => {
    const vet = fakeVet();
    const logs: string[] = [];
    provider = makeProvider(vet.run, (m) => logs.push(m));
    const doc = await makeDoc(
      config({
        bad: { command: 'npx', args: ['no-saved-answer-1'] },
        bad2: { command: 'npx', args: ['no-saved-answer-2'] },
        proxy: { command: 'npx', args: ['mcp-remote'] },
      })
    );
    provider.trigger(doc);
    await wait();
    assert.strictEqual(verdictDiagnostics(doc).length, 1);
    // One line for each different error, and no line twice.
    assert.strictEqual(logs.filter((l) => l.startsWith('vet error')).length, 2);
    provider.trigger(doc);
    await wait();
    assert.strictEqual(logs.filter((l) => l.startsWith('vet error')).length, 2);
    assert.strictEqual(vet.calls.length, 5, 'a failed lookup is tried again on the next run');
  });

  test('an answer in a form that the extension can not read shows nothing and writes one log line', async () => {
    const logs: string[] = [];
    // The form that the extension read before 0.3.0. The real command never printed it.
    let calls = 0;
    provider = makeProvider(
      async () => {
        calls += 1;
        return { name: 'mcp-remote', verdict: 'cve', cve_count: 3, cve_ids: [] };
      },
      (m) => logs.push(m)
    );
    const doc = await makeDoc(config({ proxy: { command: 'npx', args: ['mcp-remote'] } }));
    provider.trigger(doc);
    await wait();
    assert.strictEqual(verdictDiagnostics(doc).length, 0);
    assert.strictEqual(logs.length, 1);
    assert.ok(logs[0].includes('not in a form'), logs[0]);
    provider.trigger(doc);
    await wait();
    assert.strictEqual(calls, 1, 'an answer that can not be read is not asked for again');
  });

  test('two documents that start one package at the same time give one lookup', async () => {
    let calls = 0;
    provider = makeProvider(async (_b, pkg) => {
      calls += 1;
      await wait(200);
      return fakeVet().run(_b, pkg, { online: false });
    });
    const text = config({ proxy: { command: 'npx', args: ['mcp-remote'] } });
    const a = await makeDoc(text);
    const b = await makeDoc(text + '\n');
    provider.trigger(a);
    provider.trigger(b);
    await wait(900);
    assert.strictEqual(calls, 1);
    assert.strictEqual(verdictDiagnostics(a).length, 1);
    assert.strictEqual(verdictDiagnostics(b).length, 1);
  });

  test('at most 4 lookups run at one time', async () => {
    let running = 0;
    let most = 0;
    provider = makeProvider(async () => {
      running += 1;
      most = Math.max(most, running);
      await wait(50);
      running -= 1;
      return {};
    });
    const servers: Record<string, unknown> = {};
    for (let i = 0; i < 12; i++) servers[`s${i}`] = { command: 'npx', args: [`pkg-number-${i}`] };
    provider.trigger(await makeDoc(config(servers)));
    await wait(900);
    assert.strictEqual(most, 4);
  });

  test('a change of the online setting asks again', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(config({ proxy: { command: 'npx', args: ['mcp-remote'] } }));
    const settings = vscode.workspace.getConfiguration('mcp-audit');
    try {
      provider.trigger(doc);
      await wait();
      await settings.update('verdict.online', true, vscode.ConfigurationTarget.Global);
      provider.trigger(doc);
      await wait();
      assert.strictEqual(vet.calls.length, 2);
    } finally {
      await settings.update('verdict.online', undefined, vscode.ConfigurationTarget.Global);
    }
  });

  test('clear() stops a run that waits, so a closed file gets no diagnostic', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(config({ proxy: { command: 'npx', args: ['mcp-remote'] } }));
    provider.trigger(doc);
    provider.clear(doc.uri);
    await wait();
    assert.strictEqual(vet.calls.length, 0);
    assert.strictEqual(verdictDiagnostics(doc).length, 0);
  });

  test('no binary: no lookup', async () => {
    const run = sinon.stub().resolves({});
    provider = new VerdictProvider(() => { /* noop */ }, {
      runVet: run,
      probeVetSupport: () => ({ supported: true }),
      locateBinary: () => undefined,
    });
    provider.trigger(await makeDoc(config({ x: { command: 'npx', args: ['mcp-remote'] } })));
    await wait();
    sinon.assert.notCalled(run);
  });

  test('no usable vet: no lookup, and the log says why one time', async () => {
    const run = sinon.stub().resolves({});
    const logs: string[] = [];
    provider = new VerdictProvider((m) => logs.push(m), {
      runVet: run,
      probeVetSupport: () => ({ supported: false }),
      locateBinary: () => '/usr/local/bin/mcp-audit',
    });
    const doc = await makeDoc(config({ x: { command: 'npx', args: ['mcp-remote'] } }));
    provider.trigger(doc);
    await wait();
    provider.trigger(doc);
    await wait();
    sinon.assert.notCalled(run);
    assert.strictEqual(logs.length, 1);
    assert.ok(logs[0].includes('Registry verdicts are off'), logs[0]);
  });

  test('clear() removes the diagnostics of the document', async () => {
    const vet = fakeVet();
    provider = makeProvider(vet.run);
    const doc = await makeDoc(config({ proxy: { command: 'npx', args: ['mcp-remote'] } }));
    provider.trigger(doc);
    await wait();
    assert.strictEqual(verdictDiagnostics(doc).length, 1);
    provider.clear(doc.uri);
    assert.strictEqual(verdictDiagnostics(doc).length, 0);
  });
});
