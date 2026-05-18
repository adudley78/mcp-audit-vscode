/**
 * Convert mcp-audit `Finding` objects into VS Code `Diagnostic` instances.
 */

import * as vscode from 'vscode';
import { AUTO_FIXABLE_IDS, DIAGNOSTIC_SOURCE } from './constants';
import { resolveServerRange } from './lineResolver';
import type { Finding, McpSeverity } from './types';

/** Map mcp-audit severity → vscode.DiagnosticSeverity. */
export function mapSeverity(severity: McpSeverity): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return vscode.DiagnosticSeverity.Error;
    case 'MEDIUM':
      return vscode.DiagnosticSeverity.Warning;
    case 'LOW':
      return vscode.DiagnosticSeverity.Information;
    case 'INFO':
      return vscode.DiagnosticSeverity.Hint;
  }
}

/**
 * Build the hover-card message for a single finding.
 * Shown when the developer hovers over the squiggle.
 */
function buildMessage(finding: Finding): string {
  const owaspTags =
    finding.owasp_mcp_top_10.length > 0
      ? ` [${finding.owasp_mcp_top_10.join(', ')}]`
      : '';
  const cveTags =
    finding.cve.length > 0 ? `  \nCVE: ${finding.cve.join(', ')}` : '';
  const cwePart = finding.cwe ? `  \nCWE: ${finding.cwe}` : '';
  const fixHint = AUTO_FIXABLE_IDS.has(finding.id)
    ? '\n\n> Run `mcp-audit: Fix current file` to apply an automated fix.'
    : '';

  return (
    `**${finding.title}** (${finding.id})${owaspTags}\n\n` +
    `${finding.description}\n\n` +
    `**Evidence:** ${finding.evidence}\n\n` +
    `**Remediation:** ${finding.remediation}` +
    cwePart +
    cveTags +
    fixHint
  );
}

/**
 * Convert a list of `Finding` objects into `vscode.Diagnostic` objects,
 * resolved against `document`.
 *
 * Line resolution is best-effort: if the server key cannot be located in the
 * document JSON, the diagnostic falls back to line 0 (top of file).
 */
export function findingsToDiagnostics(
  findings: Finding[],
  document: vscode.TextDocument
): vscode.Diagnostic[] {
  return findings.map((finding) => {
    const range = resolveServerRange(document, finding.server);
    const severity = mapSeverity(finding.severity);
    const message = buildMessage(finding);

    const diagnostic = new vscode.Diagnostic(range, message, severity);
    diagnostic.source = DIAGNOSTIC_SOURCE;
    diagnostic.code = finding.id;

    return diagnostic;
  });
}

/**
 * Build a single INFO diagnostic for the "file too large" case.
 */
export function makeFileTooLargeDiagnostic(
  document: vscode.TextDocument
): vscode.Diagnostic {
  const range = document.lineAt(0).range;
  const diag = new vscode.Diagnostic(
    range,
    'File too large to scan with mcp-audit (limit: 5 MB)',
    vscode.DiagnosticSeverity.Information
  );
  diag.source = DIAGNOSTIC_SOURCE;
  return diag;
}

/**
 * Build a single ERROR diagnostic for an unparseable config file.
 */
export function makeMalformedJsonDiagnostic(
  document: vscode.TextDocument
): vscode.Diagnostic {
  const range = document.lineAt(0).range;
  const diag = new vscode.Diagnostic(
    range,
    'File is not valid JSON — mcp-audit cannot scan this config.',
    vscode.DiagnosticSeverity.Error
  );
  diag.source = DIAGNOSTIC_SOURCE;
  return diag;
}
