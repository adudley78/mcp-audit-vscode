#!/usr/bin/env node
/**
 * Contract test: the extension against the installed `credenzo` command.
 *
 * The unit tests read saved answers. This test starts the real command, so a
 * Credenzo release that changes the verdict document, or the way that it reads
 * a launch command, fails here and not in the editor of a user.
 *
 * 1. For each package below: runVet() + adaptVerdict() give the verdict.
 * 2. For each launch command in test/fixtures/launch-cases.json: when
 *    launchPackage() gives a package, `launch_package` of Credenzo gives the
 *    same ecosystem and name. (The extension can decline; it must not differ.)
 *
 * 3. `credenzo scan --format json` on a small config gives findings with the
 *    fields and types that src/diagnostics.ts reads, and names the server key.
 *
 * Needs: `npm run compile-tests` first; `credenzo` on PATH; a `python` that
 * can import `mcp_audit` (CREDENZO_PYTHON, default `python3`).
 *
 * Use: node scripts/contract-test.mjs [path-to-credenzo]
 */

import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const { runVet } = require(join(root, 'out-test/src/vetRunner.js'));
const { adaptVerdict } = require(join(root, 'out-test/src/verdictAdapter.js'));
const { launchPackage } = require(join(root, 'out-test/src/launchPackage.js'));
const { runScan } = require(join(root, 'out-test/src/scanner.js'));

const bin = process.argv[2] ?? 'credenzo';
const python = process.env.CREDENZO_PYTHON ?? 'python3';
let failures = 0;
const fail = (msg) => {
  failures += 1;
  console.error(`FAIL ${msg}`);
};

// ── 1. Real verdicts ────────────────────────────────────────────────────────
// The registry data changes. Each case names a fact that is stable: a package
// that the registry verifies, a pinned release with recorded CVEs, a name one
// letter from a registry name, a name that does not exist, a MAL record.
const VERDICTS = [
  [{ command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] }, ['verified']],
  [{ command: 'uvx', args: ['mcp-server-fetch'] }, ['verified']],
  [{ command: 'npx', args: ['mcp-remote@0.1.30'] }, ['cve']],
  [{ command: 'npx', args: ['@modelcontextprotocol/server-filesytem'] }, ['typosquat']],
  [{ command: 'npx', args: ['not-a-real-pkg-zz'] }, ['unknown']],
  [{ command: 'uvx', args: ['litellm==1.82.7'] }, ['malicious']],
  // A record that covers each release: a pin on a release that it does not name.
  [{ command: 'uvx', args: ['esqmcpaypallgtb==1.0.0'] }, ['malicious']],
  // The same, where the blanket range is one of two ranges.
  [{ command: 'npx', args: ['glean-mcp-server@97.98.99'] }, ['malicious']],
  [{ command: 'npx', args: ['@modelcontextprotocol/server-github'] }, ['archived', 'cve']],
];

for (const [entry, expected] of VERDICTS) {
  const label = `${entry.command} ${entry.args.join(' ')}`;
  const pkg = launchPackage(entry.command, entry.args);
  if (!pkg) {
    fail(`${label}: launchPackage gave no package`);
    continue;
  }
  try {
    const raw = await runVet(bin, pkg, { online: false });
    const result = adaptVerdict(raw, pkg);
    if (!result) fail(`${label}: the adapter can not read the answer of the real command`);
    else if (!expected.includes(result.verdict)) {
      fail(`${label}: verdict ${result.verdict}, expected ${expected.join(' or ')}`);
    } else console.log(`ok   ${label} -> ${result.verdict}`);
  } catch (err) {
    fail(`${label}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

// ── 2. launchPackage() against launch_package of Credenzo ───────────────────
const cases = JSON.parse(readFileSync(join(root, 'test/fixtures/launch-cases.json'), 'utf8'));
const mine = cases
  .map((c) => ({ ...c, got: launchPackage(c.command, c.args) }))
  .filter((c) => c.got !== null);

const PY = `
import json, sys
from mcp_audit.analyzers.supply_chain import launch_package
from mcp_audit.models import ServerConfig
out = []
for case in json.load(sys.stdin):
    server = ServerConfig(name="s", client="c", config_path="/x", command=case["command"], args=case["args"])
    found = launch_package(server)
    out.append(list(found) if found else None)
json.dump(out, sys.stdout)
`;
const py = spawnSync(python, ['-c', PY], {
  input: JSON.stringify(mine.map((c) => ({ command: c.command, args: c.args }))),
  encoding: 'utf8',
});
if (py.status !== 0) {
  fail(`python could not run launch_package: ${(py.stderr || '').trim().split('\n').pop()}`);
} else {
  const theirs = JSON.parse(py.stdout);
  mine.forEach((c, i) => {
    const label = `${c.command} ${JSON.stringify(c.args)}`;
    const t = theirs[i];
    if (!t || t[0] !== c.got.ecosystem || t[1] !== c.got.name) {
      fail(`${label}: extension ${c.got.ecosystem}:${c.got.name}, Credenzo ${t ? t.join(':') : 'no package'}`);
    }
  });
  console.log(`ok   ${mine.length} launch commands agree with launch_package of Credenzo`);
}

// ── 3. The scan answer that the diagnostics read ────────────────────────────
const dir = mkdtempSync(join(tmpdir(), 'credenzo-contract-'));
try {
  const file = join(dir, 'mcp.json');
  writeFileSync(
    file,
    JSON.stringify({
      mcpServers: {
        'contract-server': {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-filesytem', '/'],
          url: 'http://example.test/mcp',
        },
      },
    })
  );
  const scan = await runScan(bin, file, { severityThreshold: 'INFO' }, () => {});
  const SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
  const isStrings = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string');
  if (!Array.isArray(scan.findings) || scan.findings.length === 0) {
    fail('scan: no findings array, or no finding for a config with a typosquat');
  } else {
    for (const f of scan.findings) {
      const bad = [];
      for (const key of ['id', 'title', 'description', 'evidence', 'remediation', 'server']) {
        if (typeof f[key] !== 'string') bad.push(key);
      }
      if (!SEVERITIES.has(f.severity)) bad.push('severity');
      if (!isStrings(f.owasp_mcp_top_10)) bad.push('owasp_mcp_top_10');
      if (!isStrings(f.cve)) bad.push('cve');
      if (!(f.cwe === null || typeof f.cwe === 'string')) bad.push('cwe');
      if (bad.length > 0) fail(`scan: finding ${f.id}: wrong type for ${bad.join(', ')}`);
    }
    if (!scan.findings.some((f) => f.server === 'contract-server')) {
      fail('scan: no finding names the server key, so no diagnostic gets a position');
    } else console.log(`ok   scan: ${scan.findings.length} findings in the form that the diagnostics read`);
  }
} catch (err) {
  fail(`scan: ${err instanceof Error ? err.message : String(err)}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

if (failures > 0) {
  console.error(`${failures} contract check(s) failed`);
  process.exit(1);
}
console.log('contract test passed');
