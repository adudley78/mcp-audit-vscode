/**
 * mcp-audit VS Code extension — entry point.
 *
 * Activates automatically when any JSON / JSONC file is opened
 * (activationEvents: ["onLanguage:json", "onLanguage:jsonc"] in package.json).
 *
 * Wire-up:
 *  - Registers a DiagnosticCollection for all mcp-audit findings.
 *  - Listens for onDidOpenTextDocument and onDidSaveTextDocument.
 *  - Exposes three command palette commands:
 *      mcp-audit.scanCurrentFile   — manual re-scan
 *      mcp-audit.scanWorkspace     — scan every open MCP config
 *      mcp-audit.fixCurrentFile    — invoke `mcp-audit fix --path <file>`
 *  - Maintains a StatusBarItem showing grade + finding count.
 *  - Creates a dedicated OutputChannel for scan output and errors.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { locateBinary } from './binaryLocator';
import {
  DIAGNOSTIC_SOURCE,
  MAX_FILE_SIZE_BYTES,
  MCP_FILE_PATTERNS,
  MCP_PATH_SUFFIXES,
  OUTPUT_CHANNEL_NAME,
  SCAN_TIMEOUT_MS,
} from './constants';
import {
  findingsToDiagnostics,
  makeFileTooLargeDiagnostic,
  makeMalformedJsonDiagnostic,
} from './diagnostics';
import { runScan } from './scanner';
import { McpAuditStatusBar } from './statusBar';
import type { ScanResult } from './types';

// ── Internal state ─────────────────────────────────────────────────────────

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;
let statusBar: McpAuditStatusBar;

/** Tracks whether the "binary not found" warning has already been shown. */
let binaryWarningShown = false;

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * Return true if the document's file name looks like an MCP config file.
 * Checked by basename and by path suffix (for .cursor/mcp.json etc.).
 */
export function isMcpConfigFile(document: vscode.TextDocument): boolean {
  if (document.uri.scheme !== 'file') return false;

  const basename = path.basename(document.uri.fsPath);
  if ((MCP_FILE_PATTERNS as readonly string[]).includes(basename)) return true;

  const normalized = document.uri.fsPath.replace(/\\/g, '/');
  return (MCP_PATH_SUFFIXES as readonly string[]).some((suffix) =>
    normalized.endsWith(suffix)
  );
}

function log(message: string): void {
  outputChannel.appendLine(`[mcp-audit] ${message}`);
}

/** Show the binary-not-found warning exactly once per session. */
function warnBinaryNotFound(): void {
  if (binaryWarningShown) return;
  binaryWarningShown = true;
  void vscode.window
    .showWarningMessage(
      'mcp-audit binary not found. Install it with `pip install mcp-audit` or ' +
        'download a binary from https://github.com/mcp-audit/mcp-audit/releases.',
      'Install instructions'
    )
    .then((choice) => {
      if (choice === 'Install instructions') {
        void vscode.env.openExternal(
          vscode.Uri.parse(
            'https://github.com/mcp-audit/mcp-audit/blob/main/docs/ide-extension.md'
          )
        );
      }
    });
  statusBar.showNoBinary();
}

// ── Scan orchestration ─────────────────────────────────────────────────────

/**
 * Run a scan for `document` and update the DiagnosticCollection.
 * All errors are handled internally — this function never throws.
 */
async function scanDocument(document: vscode.TextDocument): Promise<void> {
  if (!isMcpConfigFile(document)) return;

  const filePath = document.uri.fsPath;
  const config = vscode.workspace.getConfiguration('mcp-audit');
  const severityThreshold = config.get<string>('severityThreshold', 'info');

  // File size guard.
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_FILE_SIZE_BYTES) {
      log(`Skipping large file (${stat.size} bytes): ${filePath}`);
      diagnosticCollection.set(document.uri, [
        makeFileTooLargeDiagnostic(document),
      ]);
      return;
    }
  } catch {
    // File may have been deleted; clear diagnostics and exit.
    diagnosticCollection.delete(document.uri);
    return;
  }

  const binaryPath = locateBinary();
  if (!binaryPath) {
    warnBinaryNotFound();
    return;
  }

  statusBar.showScanning();
  log(`Scanning: ${filePath}`);

  let result: ScanResult;
  try {
    result = await runScan(
      binaryPath,
      filePath,
      { severityThreshold },
      (line) => log(`  stderr: ${line}`)
    );
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);

    if (msg === 'TIMEOUT') {
      log(`Scan timed out after ${SCAN_TIMEOUT_MS / 1000}s: ${filePath}`);
      void vscode.window.showWarningMessage(
        `mcp-audit: scan timed out after ${SCAN_TIMEOUT_MS / 1000} seconds for ${path.basename(filePath)}.`
      );
      statusBar.hide();
      return;
    }

    // mcp-audit itself reported a config-level error (exit code 2).
    // This can happen for malformed JSON — show a single diagnostic.
    if (msg.includes('code 2') || msg.toLowerCase().includes('json')) {
      log(`Scan error (likely malformed JSON): ${msg}`);
      diagnosticCollection.set(document.uri, [
        makeMalformedJsonDiagnostic(document),
      ]);
      statusBar.hide();
      return;
    }

    log(`Scan error: ${msg}`);
    statusBar.hide();
    return;
  }

  const diagnostics = findingsToDiagnostics(result.findings, document);
  diagnosticCollection.set(document.uri, diagnostics);

  const grade = result.score?.grade ?? '?';
  statusBar.showResult(grade, result.findings.length);
  log(
    `Scan complete: ${result.findings.length} finding(s), grade ${grade} — ${filePath}`
  );
}

/** Run `mcp-audit fix --path <filePath>` and show output in the channel. */
async function fixDocument(document: vscode.TextDocument): Promise<void> {
  if (!isMcpConfigFile(document)) {
    void vscode.window.showInformationMessage(
      'mcp-audit: the current file is not an MCP config file.'
    );
    return;
  }

  const binaryPath = locateBinary();
  if (!binaryPath) {
    warnBinaryNotFound();
    return;
  }

  const filePath = document.uri.fsPath;
  outputChannel.show(true);
  log(`Running fix (dry-run): ${filePath}`);

  const { spawn } = await import('child_process');
  const proc = spawn(binaryPath, ['fix', '--path', filePath], {
    shell: false,
  });

  proc.stdout?.on('data', (chunk: Buffer) => {
    outputChannel.append(chunk.toString('utf8'));
  });
  proc.stderr?.on('data', (chunk: Buffer) => {
    outputChannel.append(chunk.toString('utf8'));
  });

  await new Promise<void>((resolve) => {
    proc.on('close', (code) => {
      log(`fix exited with code ${code}`);
      resolve();
    });
    proc.on('error', (err) => {
      log(`fix error: ${err.message}`);
      resolve();
    });
  });

  // Refresh diagnostics after fix output is shown.
  await scanDocument(document);
}

// ── Activation ─────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection(
    DIAGNOSTIC_SOURCE
  );
  outputChannel = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
  statusBar = new McpAuditStatusBar();

  context.subscriptions.push(diagnosticCollection, outputChannel, statusBar);

  // Scan on open (if enabled).
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(async (doc) => {
      const runOnOpen = vscode.workspace
        .getConfiguration('mcp-audit')
        .get<boolean>('runOnOpen', true);
      if (runOnOpen) await scanDocument(doc);
    })
  );

  // Scan on save (if enabled).
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const runOnSave = vscode.workspace
        .getConfiguration('mcp-audit')
        .get<boolean>('runOnSave', true);
      if (runOnSave) await scanDocument(doc);
    })
  );

  // Clear diagnostics when a file is closed.
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
    })
  );

  // Command: scan current file.
  context.subscriptions.push(
    vscode.commands.registerCommand('mcp-audit.scanCurrentFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      await scanDocument(editor.document);
    })
  );

  // Command: scan workspace (all open MCP config documents).
  context.subscriptions.push(
    vscode.commands.registerCommand('mcp-audit.scanWorkspace', async () => {
      const docs = vscode.workspace.textDocuments.filter(isMcpConfigFile);
      if (docs.length === 0) {
        void vscode.window.showInformationMessage(
          'mcp-audit: no MCP config files are currently open.'
        );
        return;
      }
      await Promise.all(docs.map(scanDocument));
    })
  );

  // Command: fix current file.
  context.subscriptions.push(
    vscode.commands.registerCommand('mcp-audit.fixCurrentFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      await fixDocument(editor.document);
    })
  );

  // Scan any already-open MCP config documents (e.g. re-activation).
  for (const doc of vscode.workspace.textDocuments) {
    const runOnOpen = vscode.workspace
      .getConfiguration('mcp-audit')
      .get<boolean>('runOnOpen', true);
    if (runOnOpen) void scanDocument(doc);
  }

  log('Extension activated.');
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
  outputChannel?.dispose();
  statusBar?.dispose();
}
