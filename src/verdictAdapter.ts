/**
 * Make a VetResult from the answer of `credenzo vet <package> --format json`.
 *
 * The answer is the verdict document of Credenzo (schema_version 1.x):
 * `package`, `registry`, `known_vulnerabilities`, `typosquat_of`, `malicious`,
 * `capabilities`, `links`. This module only reads those facts and puts them in
 * an order. It makes no finding of its own.
 *
 * Order: a malicious record for this release, then open CVEs, then typosquat,
 * then archived, then verified, then listed, else unknown.
 *
 * No `vscode` import: the contract test runs this file in plain Node.
 */

import type { LaunchPackage } from './launchPackage';
import type { VetResult } from './types';

const MAX_IDS = 20;
const MAX_TEXT = 200;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
// The bundled data gives the JSON address; the live data gives the page.
const VERDICT_PAGE_RE =
  /^https:\/\/(?:mcp-audit\.dev|credenzo\.io)\/(?:v1\/verdicts\/(npm|pypi)\/([a-z0-9][a-z0-9-]{0,200})\.json|servers\/(npm|pypi)\/([a-z0-9][a-z0-9-]{0,200})\/)$/;

/**
 * One text for each release, so that "1.107" and "1.107.0", or "1.2.3" and
 * "1.2.3+build", compare as equal: lowercase, no build part, no leading
 * zeros in a number, no ".0" at the end of the numbers.
 *
 * Lowercase for npm too: Credenzo compares versions without case
 * (`_same_version` in registry/malicious.py), and the extension must not
 * give a lower warning than the command for the same pin.
 *
 * Exported for unit tests.
 */
export function canonicalVersion(version: string): string {
  const v = version.trim().toLowerCase().replace(/^v/, '').split('+')[0];
  const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(v);
  if (!m) return v;
  const numbers = m[1].split('.').map((n) => n.replace(/^0+(?=\d)/, ''));
  while (numbers.length > 1 && numbers[numbers.length - 1] === '0') numbers.pop();
  return numbers.join('.') + m[2];
}

/**
 * True for a range of a MAL record that is "from release 0, with no end".
 * The ranges of a record are a union, so one such range covers each release.
 */
function isBlanketRange(range: unknown): boolean {
  const events = Array.isArray(range) ? range : isObject(range) ? range.events : null;
  if (!Array.isArray(events) || events.length !== 1 || !isObject(events[0])) return false;
  const keys = Object.keys(events[0]);
  return keys.length === 1 && keys[0] === 'introduced' && events[0].introduced === '0';
}

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
  if (!Array.isArray(raw.known_vulnerabilities)) return null;
  // A live answer (--online) has no `malicious` key when no record exists.
  const rawMalicious = raw.malicious === undefined ? [] : raw.malicious;
  if (!Array.isArray(rawMalicious)) return null;
  // An item that is not an object can be a CVE that this module can not
  // read. No verdict is better than a count that is too low.
  if (!raw.known_vulnerabilities.every(isObject) || !rawMalicious.every(isObject)) return null;

  const pinned = typeof pkg.version === 'string';
  if (asked.version !== null && !pinned) return null;

  const vulns = raw.known_vulnerabilities.filter(isObject);
  // With a version, the command gives a status for each CVE: "affected",
  // "fixed", or a different word when it can not compare the versions (it
  // exits 1 for that too). With no version, a CVE with no fix is open.
  const open = vulns.filter((v) =>
    pinned ? v.status === 'affected' : typeof v.fixed_in !== 'string' || v.fixed_in === ''
  );
  const unchecked = pinned
    ? vulns.filter((v) => v.status !== 'affected' && v.status !== 'fixed')
    : [];
  const openIds = ids([...open, ...unchecked], 'cve');
  // The command lists each MAL record of the name and does not compare it
  // with a pin. `latest_affected` is true when the record has a range with
  // no end. `versions` is the list of releases that the record names. The
  // command sets `blanket_range_ignored` when it does not use a range that
  // covers each release (a registry package with one bad release).
  //  - pin, and the record names it                         -> the verdict
  //  - pin, and the record covers each release              -> the verdict
  //  - no pin, and a range with no end                      -> the verdict
  //  - pin, and a different range (the pin is not compared) -> possible
  //  - no pin, and named releases (newest is not known)     -> possible
  //  - pin, named releases only, the pin not among them     -> other
  const malicious = rawMalicious.filter(isObject);
  const hits: Array<Record<string, unknown>> = [];
  const possible: Array<Record<string, unknown>> = [];
  const others: Array<Record<string, unknown>> = [];
  const pin = pinned ? canonicalVersion(String(pkg.version)) : null;
  for (const m of malicious) {
    const versions = Array.isArray(m.versions)
      ? m.versions.filter((v): v is string => typeof v === 'string')
      : [];
    const ranges = Array.isArray(m.ranges) ? m.ranges : [];
    const blanket = ranges.filter(isBlanketRange);
    const otherRanges = ranges.filter((r) => !isBlanketRange(r));
    // The command does not use a blanket range that it marks as ignored.
    const coversEach = blanket.length > 0 && m.blanket_range_ignored !== true;
    const openEnd = m.latest_affected === true;
    if (pin !== null) {
      if (versions.some((v) => canonicalVersion(v) === pin)) hits.push(m);
      else if (coversEach) hits.push(m);
      else if (otherRanges.length > 0 || (openEnd && blanket.length === 0)) possible.push(m);
      else others.push(m);
    } else if (openEnd) hits.push(m);
    else possible.push(m);
  }
  const typosquatOf = text(raw.typosquat_of);
  const archived = registry.archived === true;

  let verdict: VetResult['verdict'];
  if (hits.length > 0) verdict = 'malicious';
  else if (open.length + unchecked.length > 0) verdict = 'cve';
  else if (typosquatOf) verdict = 'typosquat';
  else if (archived) verdict = 'archived';
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
    if (m) registryUrl = `https://credenzo.io/servers/${m[1] ?? m[3]}/${m[2] ?? m[4]}/`;
  }

  return {
    name: asked.name,
    verdict,
    cve_count: open.length,
    cve_ids: verdict === 'malicious' ? ids(hits, 'id') : openIds,
    unchecked_cve_count: unchecked.length,
    possible_malicious_ids: ids(possible, 'id'),
    other_malicious_ids: ids(others, 'id'),
    archived,
    successor: text(registry.successor),
    fixed_cve_count: vulns.length - open.length - unchecked.length,
    pinned,
    capabilities: capabilities || null,
    typosquat_suggestion: typosquatOf,
    registry_url: registryUrl,
    maintainer: text(registry.maintainer),
  };
}
