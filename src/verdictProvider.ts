/**
 * Inline registry verdicts via `credenzo vet`.
 *
 * Behaviour:
 *  - On open/change/save of an MCP config file, find the package that each
 *    server installs (`launchPackage.ts`), call `credenzo vet` one time for
 *    each package (debounced 300 ms, 4 calls at one time), and show an inline
 *    badge and a hover card on the server key.
 *  - A server whose package the extension can not read with certainty (a
 *    local program, a URL, `python -m`, a `cmd /c` wrapper) gets no badge.
 *  - Results are cached per package for the lifetime of the session.
 *  - If the binary is missing, has no usable `vet`, or `vet` fails, the
 *    provider writes one line to the output channel and shows nothing. The
 *    scan diagnostics are not affected.
 *
 * The extension makes no finding of its own. `verdictAdapter.ts` puts the
 * facts of the verdict document in this order:
 *  - malicious  → Error diagnostic with the MAL record IDs
 *  - cve        → Warning diagnostic with the CVE IDs
 *  - typosquat  → Warning diagnostic with the registry name
 *  - verified / listed / unknown → badge only, no diagnostic
 */

import * as vscode from 'vscode';
import {
  VERDICT_DEBOUNCE_MS,
  VERDICT_DIAGNOSTIC_SOURCE,
} from './constants';
import { locateBinary } from './binaryLocator';
import { resolveAllServers } from './lineResolver';
import { launchPackage, packageKey } from './launchPackage';
import type { LaunchPackage } from './launchPackage';
import { adaptVerdict } from './verdictAdapter';
import { probeVetSupport, runVet } from './vetRunner';
import type { VetOptions } from './vetRunner';
import type { VetResult, VetSupportInfo } from './types';

/** `vet` processes at one time. */
const VET_CONCURRENCY = 4;

/** Largest number of new packages that one run looks up. */
const MAX_PACKAGES_PER_RUN = 100;

// ── Pure formatting helpers (exported for unit tests) ───────────────────────

export interface VerdictBadge {
  text: string;
  color: vscode.ThemeColor;
}

/**
 * Build the short inline text and colour for a given VetResult.
 * Rendered as the `after` pseudo-element on the server-key decoration.
 */
export function formatBadge(result: VetResult): VerdictBadge {
  const idList = (max: number): string =>
    result.cve_ids.length > 0 ? ` — ${result.cve_ids.slice(0, max).join(', ')}` : '';

  switch (result.verdict) {
    case 'malicious':
      return {
        text: `  ✖ malicious package record${idList(2)}`,
        color: new vscode.ThemeColor('editorError.foreground'),
      };
    case 'cve':
      return {
        text: `  ⚠ ${cveLabel(result)}${idList(3)}`,
        color: new vscode.ThemeColor('editorWarning.foreground'),
      };
    case 'typosquat': {
      const hint = result.typosquat_suggestion
        ? ` — did you mean ${result.typosquat_suggestion}?`
        : '';
      return {
        text: `  ⚠ possible typosquat${hint}`,
        color: new vscode.ThemeColor('editorWarning.foreground'),
      };
    }
    case 'verified':
    case 'listed': {
      const maintainer = result.maintainer
        ? ` (${shorten(result.maintainer, 40)})`
        : '';
      const head = result.verdict === 'verified' ? '✓ verified' : '• in registry, not verified';
      return {
        text: `  ${head} · ${fixedLabel(result)}${maintainer}`,
        color: new vscode.ThemeColor(
          result.verdict === 'verified' ? 'testing.iconPassed' : 'descriptionForeground'
        ),
      };
    }
    case 'unknown':
    default:
      return {
        text: '  ? not in registry — no verdict available',
        color: new vscode.ThemeColor('descriptionForeground'),
      };
  }
}

function count(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(0, Math.trunc(n)) : 0;
}

function shorten(text: string, max: number): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/**
 * The words for the open CVEs of a `cve` verdict.
 *
 * Exported for unit tests.
 */
export function cveLabel(result: VetResult): string {
  const open = count(result.cve_count);
  const unchecked = count(result.unchecked_cve_count);
  const s = (n: number): string => (n !== 1 ? 's' : '');
  if (!result.pinned) return `${open} known CVE${s(open)} with no fix recorded`;
  if (open > 0 && unchecked > 0) {
    return `${open} known CVE${s(open)} affect${open === 1 ? 's' : ''} this version, ${unchecked} not compared`;
  }
  if (open > 0) return `${open} known CVE${s(open)} affect${open === 1 ? 's' : ''} this version`;
  return `${unchecked} known CVE${s(unchecked)}: the version could not be compared`;
}

/**
 * The words for the recorded CVEs of a package that has no open CVE.
 *
 * Exported for unit tests.
 */
export function fixedLabel(result: VetResult): string {
  const fixed = count(result.fixed_cve_count);
  if (fixed === 0) return '0 known CVEs';
  const s = fixed !== 1 ? 's' : '';
  return result.pinned
    ? `${fixed} recorded CVE${s}, fixed before this version`
    : `${fixed} recorded CVE${s}, fixed in a later release`;
}

/**
 * Make text from the registry data safe to put in Markdown: the characters that
 * start a link, an image, emphasis, code or HTML are escaped.
 *
 * Exported for unit tests.
 */
export function escapeMarkdown(text: string): string {
  return String(text)
    .replace(/[\r\n]+/g, ' ')
    .replace(/[\\`*_[\]()<>!|~#]/g, '\\$&')
    // A bare address must stay text: the renderer makes a link from
    // "https://…" and from "www.…".
    .replace(/:\/\//g, ':\\/\\/')
    .replace(/\bwww\./gi, 'www\\.');
}

/**
 * True for an https URL that has no character that can end a Markdown link
 * target or start a second one.
 *
 * Exported for unit tests.
 */
export function isPlainHttpsUrl(url: string): boolean {
  return /^https:\/\/[^\s()<>"'`\\]+$/.test(url);
}

/** The only hosts that the hover links to. */
const REGISTRY_HOSTS = new Set(['credenzo.io', 'mcp-audit.dev']);

/**
 * True for a plain https URL on a Credenzo host.
 *
 * Exported for unit tests.
 */
export function isRegistryUrl(url: string): boolean {
  if (!isPlainHttpsUrl(url)) return false;
  try {
    const parsed = new URL(url);
    return (
      REGISTRY_HOSTS.has(parsed.hostname) &&
      parsed.username === '' &&
      parsed.password === '' &&
      parsed.port === ''
    );
  } catch {
    return false;
  }
}

/**
 * Build the hover MarkdownString shown when the developer hovers over the
 * decorated server-key range. Includes capabilities and the registry link.
 */
export function formatHover(result: VetResult): vscode.MarkdownString {
  // Not trusted: the hover has no command link, and a trusted hover would let
  // text from the registry data run an editor command when the user selects it.
  const md = new vscode.MarkdownString(undefined, true);
  md.isTrusted = false;
  const idText =
    result.cve_ids.length > 0 ? result.cve_ids.map(escapeMarkdown).join(', ') : '';

  switch (result.verdict) {
    case 'malicious':
      md.appendMarkdown(
        `**✖ Malicious package record**${idText ? ` — ${idText}` : ''}\n\n` +
          'OSV lists a release of this package as malicious. Read the record before you start this server.\n\n'
      );
      break;
    case 'cve':
      md.appendMarkdown(
        `**⚠ ${escapeMarkdown(cveLabel(result))}**${idText ? ` — ${idText}` : ''}\n\n`
      );
      break;
    case 'typosquat': {
      const hint = result.typosquat_suggestion
        ? ` — did you mean \`${result.typosquat_suggestion.replace(/[`\r\n]/g, '')}\`?`
        : '';
      md.appendMarkdown(`**⚠ Possible typosquat**${hint}\n\n`);
      break;
    }
    case 'verified':
    case 'listed': {
      const maintainer = result.maintainer
        ? ` (${escapeMarkdown(result.maintainer)})`
        : '';
      const head = result.verdict === 'verified' ? '✓ verified' : '• In registry, not verified';
      md.appendMarkdown(
        `**${head}${maintainer}** · ${escapeMarkdown(fixedLabel(result))}\n\n`
      );
      break;
    }
    case 'unknown':
    default:
      md.appendMarkdown(`**? Not in registry** — no verdict available\n\n`);
      break;
  }

  md.appendMarkdown(`*Package:* ${escapeMarkdown(result.name)}\n\n`);

  if (result.capabilities) {
    md.appendMarkdown(
      `*Capabilities:* ${escapeMarkdown(result.capabilities)}\n\n`
    );
  }

  if (result.registry_url && isRegistryUrl(result.registry_url)) {
    md.appendMarkdown(`[View the registry entry](${result.registry_url})`);
  }

  return md;
}

/**
 * Materialise DecorationOptions for every server whose name is present in
 * `cache`. Servers not yet resolved are silently skipped (they will be
 * repainted once the vet call completes).
 *
 * Exported for unit tests.
 */
export function buildDecorationOptions(
  servers: Array<{ name: string; range: vscode.Range }>,
  cache: Map<string, VetResult>
): vscode.DecorationOptions[] {
  const opts: vscode.DecorationOptions[] = [];
  for (const { name, range } of servers) {
    const result = cache.get(name);
    if (!result) continue;

    const badge = formatBadge(result);
    opts.push({
      range,
      hoverMessage: formatHover(result),
      renderOptions: {
        after: {
          contentText: badge.text,
          color: badge.color,
          fontStyle: 'italic',
        },
      },
    });
  }
  return opts;
}

// ── Injectable dependencies (for testing) ───────────────────────────────────

export interface VerdictDeps {
  /** Resolves with the verdict document of one package, not checked. */
  runVet?: (
    binary: string,
    pkg: LaunchPackage,
    opts: VetOptions
  ) => Promise<unknown>;
  probeVetSupport?: (binary: string) => VetSupportInfo;
  locateBinary?: () => string | undefined;
}

// ── VerdictProvider ──────────────────────────────────────────────────────────

/**
 * Manages vet-based decorations and diagnostics for MCP config documents.
 * One instance is created during `activate()` and disposed on deactivation.
 */
export class VerdictProvider implements vscode.Disposable {
  private readonly _diagnostics: vscode.DiagnosticCollection;
  private readonly _decorType: vscode.TextEditorDecorationType;

  /** Debounce handles keyed by document URI string. */
  private readonly _timers = new Map<string, ReturnType<typeof setTimeout>>();

  /** Session-level result cache keyed by package (`packageKey`). */
  private readonly _verdictCache = new Map<string, VetResult>();

  /** vet --help probe result cached per binary path. */
  private readonly _supportCache = new Map<string, VetSupportInfo>();

  /** Keys of the messages that the output channel has already. */
  private readonly _logged = new Set<string>();

  private readonly _subscriptions: vscode.Disposable[] = [];

  // Injected implementations (real in production, stubs in tests).
  private readonly _runVet: NonNullable<VerdictDeps['runVet']>;
  private readonly _probeVet: NonNullable<VerdictDeps['probeVetSupport']>;
  private readonly _locateBin: NonNullable<VerdictDeps['locateBinary']>;

  constructor(
    private readonly log: (msg: string) => void,
    deps: VerdictDeps = {}
  ) {
    this._diagnostics = vscode.languages.createDiagnosticCollection(
      VERDICT_DIAGNOSTIC_SOURCE
    );
    this._decorType = vscode.window.createTextEditorDecorationType({
      after: { margin: '0 0 0 12px' },
      rangeBehavior: vscode.DecorationRangeBehavior.ClosedClosed,
    });

    this._runVet = deps.runVet ?? runVet;
    this._probeVet = deps.probeVetSupport ?? probeVetSupport;
    this._locateBin = deps.locateBinary ?? locateBinary;

    // Repaint when a different editor becomes active (use cached results).
    this._subscriptions.push(
      vscode.window.onDidChangeActiveTextEditor((editor) => {
        if (editor) this._repaintEditor(editor);
      })
    );
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Schedule a debounced vet run for `document`.
   * Call this whenever the document is opened or its content changes/saves.
   */
  trigger(document: vscode.TextDocument): void {
    const key = document.uri.toString();
    const existing = this._timers.get(key);
    if (existing) clearTimeout(existing);

    const handle = setTimeout(() => {
      this._timers.delete(key);
      void this._run(document);
    }, VERDICT_DEBOUNCE_MS);
    this._timers.set(key, handle);
  }

  /** Remove all verdicts for a document (called when the document closes). */
  clear(uri: vscode.Uri): void {
    this._diagnostics.delete(uri);
    const uriStr = uri.toString();
    for (const editor of vscode.window.visibleTextEditors) {
      if (editor.document.uri.toString() === uriStr) {
        editor.setDecorations(this._decorType, []);
      }
    }
  }

  dispose(): void {
    for (const [, t] of this._timers) clearTimeout(t);
    this._timers.clear();
    this._diagnostics.dispose();
    this._decorType.dispose();
    for (const d of this._subscriptions) d.dispose();
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private async _run(document: vscode.TextDocument): Promise<void> {
    const binary = this._locateBin();
    if (!binary) return; // No binary: the scan path reports that.

    const support = this._getSupport(binary);
    if (!support.supported) {
      this._logOnce(
        `unsupported:${binary}`,
        'Registry verdicts are off: this command has no usable `vet`. Install Credenzo 0.33.0 or later.'
      );
      return;
    }

    // One call for each package, not for each server: two servers can start
    // the same package.
    const wanted = new Map<string, LaunchPackage>();
    for (const server of resolveAllServers(document)) {
      const pkg = launchPackage(server.command, server.args);
      if (!pkg) continue;
      const key = packageKey(pkg);
      if (!this._verdictCache.has(key)) wanted.set(key, pkg);
    }

    if (wanted.size > 0) {
      const config = vscode.workspace.getConfiguration('mcp-audit');
      const online = config.get<boolean>('verdict.online', false);
      const vetOpts: VetOptions = { online };
      const queue = [...wanted.entries()].slice(0, MAX_PACKAGES_PER_RUN);

      const worker = async (): Promise<void> => {
        for (;;) {
          const next = queue.shift();
          if (!next) return;
          const [key, pkg] = next;
          try {
            const raw = await this._runVet(binary, pkg, vetOpts);
            const result = adaptVerdict(raw, pkg);
            if (result) {
              this._verdictCache.set(key, result);
            } else {
              this._logOnce(
                `shape:${binary}`,
                'Registry verdicts: the answer of `credenzo vet` is not in a form that this extension can read. Update Credenzo and the extension.'
              );
            }
          } catch (err: unknown) {
            // One package failed: the others continue.
            this._logOnce(
              `error:${binary}`,
              `vet error: ${err instanceof Error ? err.message : String(err)}`
            );
          }
        }
      };
      await Promise.all(
        Array.from({ length: Math.min(VET_CONCURRENCY, queue.length) }, worker)
      );
    }

    this._applyVerdicts(document);
  }

  /** Each server that has a package, with the cache key in place of its name. */
  private _keyedServers(
    document: vscode.TextDocument
  ): Array<{ name: string; range: vscode.Range }> {
    const out: Array<{ name: string; range: vscode.Range }> = [];
    for (const server of resolveAllServers(document)) {
      const pkg = launchPackage(server.command, server.args);
      if (pkg) out.push({ name: packageKey(pkg), range: server.range });
    }
    return out;
  }

  private _applyVerdicts(document: vscode.TextDocument): void {
    const servers = this._keyedServers(document);
    const diagnostics: vscode.Diagnostic[] = [];
    const decorOptions = buildDecorationOptions(servers, this._verdictCache);

    for (const { name, range } of servers) {
      const result = this._verdictCache.get(name);
      if (!result) continue;
      const ids =
        result.cve_ids.length > 0 ? ` — ${result.cve_ids.join(', ')}` : '';

      if (result.verdict === 'malicious') {
        const diag = new vscode.Diagnostic(
          range,
          `${result.name}: OSV lists a release of this package as malicious${ids}`,
          vscode.DiagnosticSeverity.Error
        );
        diag.source = VERDICT_DIAGNOSTIC_SOURCE;
        diag.code = result.cve_ids[0] ?? 'MALICIOUS';
        diagnostics.push(diag);
      } else if (result.verdict === 'cve') {
        const diag = new vscode.Diagnostic(
          range,
          `${result.name}: ${cveLabel(result)}${ids}`,
          vscode.DiagnosticSeverity.Warning
        );
        diag.source = VERDICT_DIAGNOSTIC_SOURCE;
        diag.code = result.cve_ids[0] ?? 'CVE';
        diagnostics.push(diag);
      } else if (result.verdict === 'typosquat') {
        const suggestion = result.typosquat_suggestion
          ? ` — did you mean "${result.typosquat_suggestion}"?`
          : '';
        const diag = new vscode.Diagnostic(
          range,
          `${result.name}: possible typosquat${suggestion}`,
          vscode.DiagnosticSeverity.Warning
        );
        diag.source = VERDICT_DIAGNOSTIC_SOURCE;
        diag.code = 'TYPOSQUAT';
        diagnostics.push(diag);
      }
      // 'verified', 'listed' and 'unknown' emit no diagnostics.
    }

    this._diagnostics.set(document.uri, diagnostics);

    for (const editor of vscode.window.visibleTextEditors) {
      if (editor.document.uri.toString() === document.uri.toString()) {
        editor.setDecorations(this._decorType, decorOptions);
      }
    }
  }

  /** Write `message` to the output channel one time for each `key`. */
  private _logOnce(key: string, message: string): void {
    if (this._logged.has(key)) return;
    this._logged.add(key);
    this.log(message);
  }

  /** Repaint using cached data only — no subprocess call. */
  private _repaintEditor(editor: vscode.TextEditor): void {
    const servers = this._keyedServers(editor.document);
    if (!servers.some((s) => this._verdictCache.has(s.name))) return;
    this._applyVerdicts(editor.document);
  }

  private _getSupport(binaryPath: string): VetSupportInfo {
    if (!this._supportCache.has(binaryPath)) {
      this._supportCache.set(binaryPath, this._probeVet(binaryPath));
    }
    return this._supportCache.get(binaryPath)!;
  }
}
