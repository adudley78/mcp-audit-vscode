/**
 * Make a VetResult from the answer of `credenzo vet <package> --format json`.
 *
 * The answer is the verdict document of Credenzo (schema_version 1.x):
 * `package`, `registry`, `known_vulnerabilities`, `typosquat_of`, `malicious`,
 * `capabilities`, `links`. This module only reads those facts and puts them in
 * an order. It makes no finding of its own.
 *
 * Order: malicious, then open CVEs, then typosquat, then verified, then
 * listed, else unknown.
 *
 * No `vscode` import: the contract test runs this file in plain Node.
 */

import type { LaunchPackage } from './launchPackage';
import type { VetResult } from './types';

const MAX_IDS = 20;
const MAX_TEXT = 200;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const VERDICT_PAGE_RE =
  /^https:\/\/(?:mcp-audit\.dev|credenzo\.io)\/v1\/verdicts\/(npm|pypi)\/([a-z0-9][a-z0-9-]{0,200})\.json$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, MAX_TEXT) : null;
}

function ids(items: unknown[], key: string): string[] {
  const out: string[] = [];
  for (const item of items) {
    if (!isObject(item)) continue;
    const id = item[key];
    if (typeof id === 'string' && ID_RE.test(id) && !out.includes(id)) out.push(id);
    if (out.length >= MAX_IDS) break;
  }
  return out;
}

/**
 * Give the VetResult for `raw`, or null when `raw` is not a verdict document
 * that this module can read, or is about a different package than `asked`.
 */
export function adaptVerdict(raw: unknown, asked: LaunchPackage): VetResult | null {
  if (!isObject(raw)) return null;
  if (typeof raw.schema_version !== 'string' || !raw.schema_version.startsWith('1.')) {
    return null;
  }
  const pkg = raw.package;
  const registry = raw.registry;
  if (!isObject(pkg) || !isObject(registry)) return null;
  // A release that can not read "name@1.2.3" looks up the whole text. Its
  // answer is then about a different name: no verdict.
  if (pkg.name !== asked.name || pkg.ecosystem !== asked.ecosystem) return null;
  if (!Array.isArray(raw.known_vulnerabilities) || !Array.isArray(raw.malicious)) return null;

  const pinned = typeof pkg.version === 'string';
  if (asked.version !== null && !pinned) return null;

  const vulns = raw.known_vulnerabilities.filter(isObject);
  // With a version, the command gives a status for each CVE: "affected",
  // "fixed", or a different word when it can not compare the versions (it
  // exits 1 for that too). With no version, a CVE with no fix is open.
  const open = vulns.filter((v) =>
    pinned ? v.status === 'affected' : v.fixed_in === null || v.fixed_in === undefined
  );
  const unchecked = pinned
    ? vulns.filter((v) => v.status !== 'affected' && v.status !== 'fixed')
    : [];
  const openIds = ids([...open, ...unchecked], 'cve');
  const malicious = raw.malicious.filter(isObject);
  const typosquatOf = text(raw.typosquat_of);

  let verdict: VetResult['verdict'];
  if (malicious.length > 0) verdict = 'malicious';
  else if (open.length + unchecked.length > 0) verdict = 'cve';
  else if (typosquatOf) verdict = 'typosquat';
  else if (registry.verified === true) verdict = 'verified';
  else if (registry.listed === true) verdict = 'listed';
  else verdict = 'unknown';

  const capabilities = Array.isArray(raw.capabilities)
    ? raw.capabilities
        .filter((c): c is string => typeof c === 'string' && /^[a-z0-9_]{1,40}$/.test(c))
        .slice(0, 20)
        .map((c) => c.replace(/_/g, ' '))
        .join(', ')
    : '';

  // The verdict page is JSON for programs. The page for a person is on
  // credenzo.io, and only a listed package has one.
  let registryUrl: string | null = null;
  const links = raw.links;
  if (registry.listed === true && isObject(links) && typeof links.verdict_page === 'string') {
    const m = VERDICT_PAGE_RE.exec(links.verdict_page);
    if (m) registryUrl = `https://credenzo.io/servers/${m[1]}/${m[2]}/`;
  }

  return {
    name: asked.name,
    verdict,
    cve_count: verdict === 'malicious' ? 0 : open.length,
    cve_ids: verdict === 'malicious' ? ids(malicious, 'id') : openIds,
    unchecked_cve_count: verdict === 'malicious' ? 0 : unchecked.length,
    fixed_cve_count: vulns.length - open.length - unchecked.length,
    pinned,
    capabilities: capabilities || null,
    typosquat_suggestion: typosquatOf,
    registry_url: registryUrl,
    maintainer: text(registry.maintainer),
  };
}
