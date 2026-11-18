/**
 * Tests for adaptVerdict() on the saved real answers of
 * `credenzo vet --format json` (test/fixtures/vet).
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { adaptVerdict } from '../../src/verdictAdapter';
import type { LaunchPackage } from '../../src/launchPackage';

const FIXTURES = path.resolve(__dirname, '../../../test/fixtures/vet');

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(
    fs.readFileSync(path.join(FIXTURES, `${name}.json`), 'utf8')
  ) as Record<string, unknown>;
}

const npm = (name: string, version: string | null = null): LaunchPackage => ({
  ecosystem: 'npm',
  name,
  version,
});
const pypi = (name: string): LaunchPackage => ({ ecosystem: 'pypi', name, version: null });

const FS = '@modelcontextprotocol/server-filesystem';

suite('verdictAdapter — saved real answers', () => {
  test('verified, no pin: the two fixed CVEs are counted as fixed, not open', () => {
    const r = adaptVerdict(fixture('verified-unpinned'), npm(FS));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'verified');
    assert.strictEqual(r.cve_count, 0);
    assert.strictEqual(r.fixed_cve_count, 2);
    assert.strictEqual(r.pinned, false);
    assert.strictEqual(r.maintainer, 'Anthropic');
    assert.strictEqual(r.capabilities, 'file read, file write');
    assert.strictEqual(
      r.registry_url,
      'https://credenzo.io/servers/npm/at-modelcontextprotocol-server-filesystem/'
    );
  });

  test('verified on PyPI: the link is the PyPI page', () => {
    const r = adaptVerdict(fixture('verified-pypi'), pypi('mcp-server-fetch'));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'verified');
    assert.strictEqual(r.registry_url, 'https://credenzo.io/servers/pypi/mcp-server-fetch/');
  });

  test('pinned version: the CVEs with status affected are open, the fixed one is not', () => {
    const r = adaptVerdict(fixture('cve-pinned'), npm('mcp-remote', '0.1.30'));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'cve');
    assert.strictEqual(r.pinned, true);
    assert.strictEqual(r.cve_count, 6);
    assert.strictEqual(r.unchecked_cve_count, 0);
    assert.strictEqual(r.fixed_cve_count, 1);
    assert.ok(r.cve_ids.includes('CVE-2026-51996'));
    assert.ok(!r.cve_ids.includes('CVE-2025-6514'));
  });

  test('no pin: only the CVE with no fix is open', () => {
    const r = adaptVerdict(fixture('cve-unpinned'), npm('mcp-remote'));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'cve');
    assert.strictEqual(r.cve_count, 1);
    assert.deepStrictEqual(r.cve_ids, ['CVE-2026-108716']);
    assert.strictEqual(r.fixed_cve_count, 6);
  });

  test('typosquat: the registry name is the suggestion, and there is no link', () => {
    const r = adaptVerdict(
      fixture('typosquat'),
      npm('@modelcontextprotocol/server-filesytem')
    );
    assert.ok(r);
    assert.strictEqual(r.verdict, 'typosquat');
    assert.strictEqual(r.typosquat_suggestion, FS);
    assert.strictEqual(r.registry_url, null, 'a package that is not listed has no page');
  });

  test('unknown', () => {
    const r = adaptVerdict(fixture('unknown'), npm('not-a-real-pkg-zz'));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'unknown');
    assert.strictEqual(r.registry_url, null);
    assert.strictEqual(r.capabilities, null);
  });

  test('malicious: the MAL record ID is given', () => {
    const r = adaptVerdict(fixture('malicious'), pypi('claude-lite'));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'malicious');
    assert.deepStrictEqual(r.cve_ids, ['MAL-2026-2269']);
  });
});

suite('verdictAdapter — order and refusals', () => {
  test('malicious comes before CVEs, CVEs before typosquat, typosquat before verified', () => {
    const base = fixture('cve-unpinned');
    const withMal = { ...base, malicious: [{ id: 'MAL-2026-1' }], typosquat_of: 'x' };
    assert.strictEqual(adaptVerdict(withMal, npm('mcp-remote'))?.verdict, 'malicious');
    const withTypo = { ...base, typosquat_of: 'x' };
    assert.strictEqual(adaptVerdict(withTypo, npm('mcp-remote'))?.verdict, 'cve');
    const verifiedTypo = { ...fixture('verified-pypi'), typosquat_of: 'x' };
    assert.strictEqual(
      adaptVerdict(verifiedTypo, pypi('mcp-server-fetch'))?.verdict,
      'typosquat'
    );
  });

  test('listed and not verified is "listed", not "unknown"', () => {
    const base = fixture('cve-unpinned');
    const noVulns = { ...base, known_vulnerabilities: [] };
    assert.strictEqual(adaptVerdict(noVulns, npm('mcp-remote'))?.verdict, 'listed');
  });

  test('a status that is not affected and not fixed is "not compared", and the verdict is cve', () => {
    const base = fixture('cve-pinned');
    const vulns = [{ cve: 'CVE-2026-1', status: 'undecidable', fixed_in: '2026.1.1' }];
    const r = adaptVerdict({ ...base, known_vulnerabilities: vulns }, npm('mcp-remote', '0.1.30'));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'cve');
    assert.strictEqual(r.cve_count, 0);
    assert.strictEqual(r.unchecked_cve_count, 1);
    assert.deepStrictEqual(r.cve_ids, ['CVE-2026-1']);
  });

  test('an answer about a different package gives no verdict', () => {
    assert.strictEqual(adaptVerdict(fixture('unknown'), npm('other')), null);
    assert.strictEqual(adaptVerdict(fixture('verified-pypi'), npm('mcp-server-fetch')), null);
  });

  test('a release that did not judge the pinned version gives no verdict', () => {
    // An old release looks up "name@1.2.3" as a name; one that drops the
    // version would answer with no package.version.
    assert.strictEqual(adaptVerdict(fixture('cve-unpinned'), npm('mcp-remote', '0.1.30')), null);
  });

  test('a form that is not the verdict document gives no verdict', () => {
    for (const bad of [
      null,
      [],
      'text',
      {},
      { name: 'mcp-remote', verdict: 'cve', cve_count: 3 },
      { ...fixture('unknown'), schema_version: '2.0.0' },
      { ...fixture('unknown'), known_vulnerabilities: 'none' },
      { ...fixture('unknown'), registry: null },
    ]) {
      assert.strictEqual(adaptVerdict(bad, npm('not-a-real-pkg-zz')), null, JSON.stringify(bad));
    }
  });

  test('an ID or a link that is not in the known form is left out', () => {
    const base = fixture('verified-unpinned');
    const r = adaptVerdict(
      {
        ...base,
        known_vulnerabilities: [{ cve: '[x](command:y)', fixed_in: null }],
        links: { verdict_page: 'https://evil.example/v1/verdicts/npm/x.json' },
        capabilities: ['file_read', '[x](command:y)', 7],
      },
      npm(FS)
    );
    assert.ok(r);
    assert.strictEqual(r.verdict, 'cve');
    assert.deepStrictEqual(r.cve_ids, []);
    assert.strictEqual(r.registry_url, null);
    assert.strictEqual(r.capabilities, 'file read');
  });
});
