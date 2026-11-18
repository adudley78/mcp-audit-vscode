/**
 * Tests for adaptVerdict() on the saved real answers of
 * `credenzo vet --format json` (test/fixtures/vet).
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { adaptVerdict, canonicalVersion } from '../../src/verdictAdapter';
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
const pypi = (name: string, version: string | null = null): LaunchPackage => ({
  ecosystem: 'pypi',
  name,
  version,
});

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

  test('a MAL record that names the pinned version is the verdict', () => {
    const r = adaptVerdict(fixture('malicious-pinned'), pypi('litellm', '1.82.7'));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'malicious');
    assert.deepStrictEqual(r.cve_ids, ['MAL-2026-2144']);
    assert.deepStrictEqual(r.other_malicious_ids, []);
    assert.deepStrictEqual(r.possible_malicious_ids, []);
    assert.ok(r.cve_count > 0, 'the CVE count is kept');
  });

  test('the pinned version is compared as a release, not as text', () => {
    // uv installs 1.107.0 for "litellm==1.107"; the record names "1.107.0".
    const doc = fixture('malicious-pinned');
    for (const pin of ['1.107', '1.107.0', '1.107.0.0', '1.082.7']) {
      const asked = pypi('litellm', pin);
      const answer = { ...doc, package: { ...(doc.package as object), version: pin } };
      assert.strictEqual(adaptVerdict(answer, asked)?.verdict, 'malicious', pin);
    }
    assert.strictEqual(canonicalVersion('2.1.1+x'), canonicalVersion('2.1.1'));
    assert.strictEqual(canonicalVersion('1.0.0'), '1');
    assert.strictEqual(canonicalVersion('1.0.0-rc1'), '1-rc1');
    assert.strictEqual(canonicalVersion('0.0'), '0');
    // As Credenzo compares: without case.
    assert.strictEqual(canonicalVersion('0.140.0-BETA.0'), canonicalVersion('0.140.0-beta.0'));
    // Two different releases must never compare as equal.
    for (const [a, b] of [
      ['1.0.0-rc1', '1.0.0'],
      ['1.10', '1.1'],
      ['1.0.0-rc1', '1.0.0-rc2'],
      ['10.0', '1.0'],
      ['1.0.1', '1.0.10'],
      ['1.0.4-2', '1.0.4'],
    ]) {
      assert.notStrictEqual(canonicalVersion(a), canonicalVersion(b), `${a} ${b}`);
    }
  });

  test('a pin, and a record that covers each release: the verdict, with no comparison', () => {
    const doc = fixture('malicious-not-this');
    const blanket = [
      [[{ introduced: '0' }]],
      [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }],
      // The ranges of a record are a union: one blanket range is enough.
      [[{ introduced: '1.0.0' }], [{ introduced: '0' }]],
      [[{ introduced: '0' }], [{ introduced: '5.0.0' }, { fixed: '6.0.0' }]],
    ];
    for (const ranges of blanket) {
      const records = (doc.malicious as Array<Record<string, unknown>>).map((m) => ({
        ...m,
        versions: [],
        ranges,
        latest_affected: true,
      }));
      const r = adaptVerdict({ ...doc, malicious: records }, pypi('litellm', '1.83.0'));
      assert.strictEqual(r?.verdict, 'malicious', JSON.stringify(ranges));
    }
    // The command says that it does not use the range: it is not the verdict.
    const ignored = (doc.malicious as Array<Record<string, unknown>>).map((m) => ({
      ...m,
      ranges: [[{ introduced: '0' }]],
      blanket_range_ignored: true,
    }));
    const r = adaptVerdict({ ...doc, malicious: ignored }, pypi('litellm', '1.83.0'));
    assert.strictEqual(r?.verdict, 'cve');
    assert.deepStrictEqual(r?.other_malicious_ids, ['MAL-2026-2144']);
    assert.deepStrictEqual(r?.possible_malicious_ids, []);
  });

  test('a MAL record for other releases is a note; the CVEs stay the verdict', () => {
    const r = adaptVerdict(fixture('malicious-not-this'), pypi('litellm', '1.83.0'));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'cve');
    assert.strictEqual(r.cve_count, 17);
    // The registry field `cve` holds CVE and GHSA IDs. No MAL ID is among them.
    assert.ok(r.cve_ids.every((id) => /^(CVE|GHSA)-/.test(id)), r.cve_ids.join(' '));
    assert.deepStrictEqual(r.other_malicious_ids, ['MAL-2026-2144']);
    assert.deepStrictEqual(r.possible_malicious_ids, []);
  });

  test('no pin, and a record that names releases: the newest release is not known, so "possible"', () => {
    const r = adaptVerdict(fixture('malicious-other'), pypi('claude-lite'));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'unknown');
    assert.deepStrictEqual(r.possible_malicious_ids, ['MAL-2026-2269']);
    assert.deepStrictEqual(r.other_malicious_ids, []);
  });

  test('no pin, and a record with a range with no end: the verdict', () => {
    const doc = fixture('malicious-other');
    const records = (doc.malicious as Array<Record<string, unknown>>).map((m) => ({
      ...m,
      latest_affected: true,
    }));
    const r = adaptVerdict({ ...doc, malicious: records }, pypi('claude-lite'));
    assert.strictEqual(r?.verdict, 'malicious');
    assert.deepStrictEqual(r?.cve_ids, ['MAL-2026-2269']);
  });

  test('a pin, and a record with a range: not compared, so "possible", not "this version"', () => {
    const doc = fixture('malicious-not-this');
    for (const change of [
      { latest_affected: true },
      { ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '10.0.1' }] }] },
      { ranges: [[{ introduced: '0' }, { fixed: '2.0.0' }]] },
      // An ignored blanket range does not hide a second range.
      {
        ranges: [[{ introduced: '0' }], [{ introduced: '1.0.0' }, { fixed: '2.0.0' }]],
        blanket_range_ignored: true,
      },
    ]) {
      const records = (doc.malicious as Array<Record<string, unknown>>).map((m) => ({
        ...m,
        ...change,
      }));
      const r = adaptVerdict({ ...doc, malicious: records }, pypi('litellm', '1.83.0'));
      assert.strictEqual(r?.verdict, 'cve');
      assert.deepStrictEqual(r?.possible_malicious_ids, ['MAL-2026-2144']);
      assert.deepStrictEqual(r?.other_malicious_ids, []);
    }
  });

  test('an archived package is "archived", not "verified"', () => {
    const r = adaptVerdict(
      fixture('archived'),
      npm('@modelcontextprotocol/server-github')
    );
    assert.ok(r);
    assert.strictEqual(r.verdict, 'archived');
    assert.strictEqual(r.archived, true);
    assert.strictEqual(r.successor, 'github/github-mcp-server');
  });

  test('a live answer (--online) has no malicious key and a page link; both are read', () => {
    const doc = fixture('online-listed');
    assert.strictEqual('malicious' in doc, false, 'the saved live answer has no malicious key');
    const r = adaptVerdict(doc, npm('mcp-remote'));
    assert.ok(r);
    assert.strictEqual(r.verdict, 'cve');
    assert.strictEqual(r.registry_url, 'https://credenzo.io/servers/npm/mcp-remote/');
  });
});

suite('verdictAdapter — order and refusals', () => {
  test('malicious comes before CVEs, CVEs before typosquat, typosquat before verified', () => {
    const base = fixture('cve-unpinned');
    const withMal = {
      ...base,
      malicious: [{ id: 'MAL-2026-1', latest_affected: true }],
      typosquat_of: 'x',
    };
    assert.strictEqual(adaptVerdict(withMal, npm('mcp-remote'))?.verdict, 'malicious');
    const withTypo = { ...base, typosquat_of: 'x' };
    assert.strictEqual(adaptVerdict(withTypo, npm('mcp-remote'))?.verdict, 'cve');
    const verifiedTypo = { ...fixture('verified-pypi'), typosquat_of: 'x' };
    assert.strictEqual(
      adaptVerdict(verifiedTypo, pypi('mcp-server-fetch'))?.verdict,
      'typosquat'
    );
  });

  test('archived comes after CVEs and typosquat, and before verified', () => {
    const archived = fixture('archived');
    assert.strictEqual(
      adaptVerdict({ ...archived, typosquat_of: 'x' }, npm('@modelcontextprotocol/server-github'))
        ?.verdict,
      'typosquat'
    );
    const withCve = { ...archived, known_vulnerabilities: [{ cve: 'CVE-2026-1', fixed_in: null }] };
    const r = adaptVerdict(withCve, npm('@modelcontextprotocol/server-github'));
    assert.strictEqual(r?.verdict, 'cve');
    assert.strictEqual(r?.archived, true, 'the archived fact is kept for the hover');
  });

  test('an empty fixed_in is "no fix"; an item that is not an object gives no verdict', () => {
    const base = fixture('verified-pypi');
    const r = adaptVerdict(
      { ...base, known_vulnerabilities: [{ cve: 'CVE-2026-1', fixed_in: '' }] },
      pypi('mcp-server-fetch')
    );
    assert.strictEqual(r?.verdict, 'cve');
    assert.strictEqual(
      adaptVerdict({ ...base, known_vulnerabilities: ['CVE-2026-1'] }, pypi('mcp-server-fetch')),
      null
    );
    assert.strictEqual(
      adaptVerdict({ ...base, malicious: ['MAL-2026-1'] }, pypi('mcp-server-fetch')),
      null
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
