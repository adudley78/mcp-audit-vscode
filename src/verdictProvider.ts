/**
 * Inline registry verdicts via `mcp-audit vet` (requires mcp-audit >= 1.1.0).
 *
 * Behaviour:
 *  - On open/change/save of any MCP config file the extension already watches,
 *    extract every server key, call `mcp-audit vet` (debounced 300 ms), and
 *    render inline decorations + hover cards.
 *  - Results are cached per server name for the lifetime of the VS Code session
 *    so repeated saves don't re-invoke vet for already-known packages.
 *  - If `vet --help` shows that the binary supports multiple names in one call
 *    (supportsBatch), a single subprocess is used; otherwise one per name.
 *  - If the binary is missing, too old (<1.1.0), or vet fails, the provider
 *    degrades silently — existing scan diagnostics are unaffected.
 *
 * Diagnostic rules (ADR-0002: no detection logic in TypeScript):
 *  - verdict === 'cve'       → Warning diagnostic with CVE IDs
 *  - verdict === 'typosquat' → Warning diagnostic "did you mean X?"
 *  - verdict === 'unknown'   → hint decoration only, no squiggle
 *  - verdict === 'verified'  → decoration only, no diagnostic
 *
 * Inline badge text (after the server key):
 *  ✓ verified · 0 known CVEs (Maintainer)
 *  ⚠ N known CVEs — CVE-YYYY-NNNNN
 *  ⚠ possible typosquat — did you mean real-package?
 *  ? not in registry — no verdict available
 *
 * The hover card adds a capabilities one-liner and a link to mcp-audit.dev.
 */

import * as vscode from 'vscode';
import {
  VERDICT_DEBOUNCE_MS,
  VERDICT_DIAGNOSTIC_SOURCE,
} from './constants';
import { locateBinary } from './binaryLocator';
import { resolveAllServers } from './lineResolver';
import { probeVetSupport, runVet } from './vetRunner';
import type { VetOptions } from './vetRunner';
import type { VetResult, VetSupportInfo } from './types';

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
  switch (result.verdict) {
    case 'verified': {
      const maintainer = result.maintainer ? ` (${result.maintainer})` : '';
      const cveLabel =
        result.cve_count === 0
          ? '0 known CVEs'
          : `${result.cve_count} known CVE${result.cve_count !== 1 ? 's' : ''}`;
      return {
        text: `  ✓ verified · ${cveLabel}${maintainer}`,
        color: new vscode.ThemeColor('testing.iconPassed'),
      };
    }
    case 'cve': {
      const ids =
        result.cve_ids.length > 0
          ? ` — ${result.cve_ids.slice(0, 3).join(', ')}`
          : '';
      const n = result.cve_count;
      return {
        text: `  ⚠ ${n} known CVE${n !== 1 ? 's' : ''}${ids}`,
        color: new vscode.ThemeColor('editorWarning.foreground'),
      };
    }
    case 'typosquat': {
      const hint = result.typosquat_suggestion
        ? ` — did you mean ${result.typosquat_suggestion}?`
        : '';
      return {
        text: `  ⚠ possible typosquat${hint}`,
        color: new vscode.ThemeColor('editorWarning.foreground'),
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

/**
 * Build the hover MarkdownString shown when the developer hovers over the
 * decorated server-key range. Includes capabilities and mcp-audit.dev link.
 */
export function formatHover(result: VetResult): vscode.MarkdownString {
  const md = new vscode.MarkdownString(undefined, true);
  md.isTrusted = true;

  switch (result.verdict) {
    case 'verified': {
      const maintainer = result.maintainer ? ` (${result.maintainer})` : '';
      const cveLabel =
        result.cve_count === 0
          ? '0 known CVEs'
          : `${result.cve_count} known CVE${result.cve_count !== 1 ? 's' : ''}`;
      md.appendMarkdown(`**✓ verified${maintainer}** · ${cveLabel}\n\n`);
      break;
    }
    case 'cve': {
      const ids =
        result.cve_ids.length > 0 ? result.cve_ids.join(', ') : 'see registry';
      const n = result.cve_count;
      md.appendMarkdown(
        `**⚠ ${n} known CVE${n !== 1 ? 's' : ''}** — ${ids}\n\n`
      );
      break;
    }
    case 'typosquat': {
      const hint = result.typosquat_suggestion
        ? ` — did you mean \`${result.typosquat_suggestion}\`?`
        : '';
      md.appendMarkdown(`**⚠ Possible typosquat**${hint}\n\n`);
      break;
    }
    case 'unknown':
    default:
      md.appendMarkdown(`**? Not in registry** — no verdict available\n\n`);
      break;
  }

  if (result.capabilities) {
    md.appendMarkdown(`*Capabilities:* ${result.capabilities}\n\n`);
  }

  if (result.registry_url) {
    md.appendMarkdown(
      `[View on mcp-audit.dev](${result.registry_url})`
    );
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
  runVet?: (
    binary: string,
    names: string[],
    opts: VetOptions
  ) => Promise<VetResult[]>;
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

  /** Session-level result cache keyed by server name. */
  private readonly _verdictCache = new Map<string, VetResult>();

  /** vet --help probe result cached per binary path. */
  private readonly _supportCache = new Map<string, VetSupportInfo>();

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
    if (!binary) return; // No binary — degrade silently.

    const support = this._getSupport(binary);
    if (!support.supported) return; // Binary too old — degrade silently.

    const servers = resolveAllServers(document);
    if (servers.length === 0) return;

    const uncached = servers.filter((s) => !this._verdictCache.has(s.name));
    if (uncached.length > 0) {
      const config = vscode.workspace.getConfiguration('mcp-audit');
      const online = config.get<boolean>('verdict.online', false);
      const vetOpts: VetOptions = { online };

      try {
        if (support.supportsBatch) {
          const results = await this._runVet(
            binary,
            uncached.map((s) => s.name),
            vetOpts
          );
          for (const r of results) this._verdictCache.set(r.name, r);
        } else {
          await Promise.all(
            uncached.map(async (s) => {
              try {
                const [r] = await this._runVet(binary, [s.name], vetOpts);
                if (r) this._verdictCache.set(r.name, r);
              } catch {
                // Per-server vet failure — skip; degrade silently.
              }
            })
          );
        }
      } catch (err: unknown) {
        // Batch call failure — fall through and paint whatever is cached.
        this.log(
          `vet error: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    this._applyVerdicts(document);
  }

  private _applyVerdicts(document: vscode.TextDocument): void {
    const servers = resolveAllServers(document);
    const diagnostics: vscode.Diagnostic[] = [];
    const decorOptions = buildDecorationOptions(servers, this._verdictCache);

    for (const { name, range } of servers) {
      const result = this._verdictCache.get(name);
      if (!result) continue;

      if (result.verdict === 'cve' && result.cve_count > 0) {
        const ids =
          result.cve_ids.length > 0 ? ` — ${result.cve_ids.join(', ')}` : '';
        const n = result.cve_count;
        const diag = new vscode.Diagnostic(
          range,
          `${n} known CVE${n !== 1 ? 's' : ''}${ids}`,
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
          `Possible typosquat${suggestion}`,
          vscode.DiagnosticSeverity.Warning
        );
        diag.source = VERDICT_DIAGNOSTIC_SOURCE;
        diag.code = 'TYPOSQUAT';
        diagnostics.push(diag);
      }
      // 'verified' and 'unknown' emit no diagnostics.
    }

    this._diagnostics.set(document.uri, diagnostics);

    for (const editor of vscode.window.visibleTextEditors) {
      if (editor.document.uri.toString() === document.uri.toString()) {
        editor.setDecorations(this._decorType, decorOptions);
      }
    }
  }

  /** Repaint using cached data only — no subprocess call. */
  private _repaintEditor(editor: vscode.TextEditor): void {
    const servers = resolveAllServers(editor.document);
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
