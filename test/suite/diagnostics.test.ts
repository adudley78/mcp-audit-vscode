/**
 * Unit tests for findingsToDiagnostics() and severity mapping.
 * Covers story test cases:
 *   - test_diagnostic_created_for_cred_finding
 *   - test_no_diagnostic_on_clean_scan
 *   - test_severity_mapping
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import {
  findingsToDiagnostics,
  makeMalformedJsonDiagnostic,
  mapSeverity,
} from '../../src/diagnostics';
import type { Finding } from '../../src/types';

// ── Fixture helpers ────────────────────────────────────────────────────────

function makeFinding(
  overrides: Partial<Finding> = {}
): Finding {
  return {
    id: 'CRED-001',
    severity: 'CRITICAL',
    analyzer: 'credentials',
    client: 'Claude Desktop',
    server: 'test-server',
    tool: null,
    title: 'Credential Exposure',
    description: 'Plaintext API key in env block.',
    evidence: 'OPENAI_API_KEY=sk-...',
    remediation: 'Replace with an environment variable reference.',
    cwe: 'CWE-312',
    finding_path: null,
    owasp_mcp_top_10: ['MCP03'],
    cve: [],
    ...overrides,
  };
}

/** Return a minimal in-memory TextDocument containing `text`. */
async function makeDocument(text: string): Promise<vscode.TextDocument> {
  return vscode.workspace.openTextDocument({
    content: text,
    language: 'json',
  });
}

// ── Test suite ─────────────────────────────────────────────────────────────

suite('diagnostics — findingsToDiagnostics()', () => {
  test('test_diagnostic_created_for_cred_finding — CRED-001 produces one Error diagnostic', async () => {
    const json = JSON.stringify({
      mcpServers: {
        'test-server': { command: 'node', args: [] },
      },
    });
    const doc = await makeDocument(json);
    const finding = makeFinding();

    const diags = findingsToDiagnostics([finding], doc);

    assert.strictEqual(diags.length, 1);
    assert.strictEqual(diags[0].severity, vscode.DiagnosticSeverity.Error);
    assert.ok(diags[0].message.includes('CRED-001'));
    assert.ok(diags[0].message.includes('Credential Exposure'));
    assert.strictEqual(diags[0].code, 'CRED-001');
    assert.strictEqual(diags[0].source, 'mcp-audit');
  });

  test('test_no_diagnostic_on_clean_scan — empty findings produces empty array', async () => {
    const json = JSON.stringify({ mcpServers: {} });
    const doc = await makeDocument(json);

    const diags = findingsToDiagnostics([], doc);

    assert.strictEqual(diags.length, 0);
  });

  test('hover card includes OWASP tag when present', async () => {
    const doc = await makeDocument(
      JSON.stringify({ mcpServers: { 'test-server': {} } })
    );
    const finding = makeFinding({ owasp_mcp_top_10: ['MCP03', 'MCP10'] });

    const diags = findingsToDiagnostics([finding], doc);

    assert.ok(diags[0].message.includes('MCP03'));
    assert.ok(diags[0].message.includes('MCP10'));
  });

  test('auto-fixable finding includes fix hint in message', async () => {
    const doc = await makeDocument(
      JSON.stringify({ mcpServers: { 'test-server': {} } })
    );
    const finding = makeFinding({ id: 'CRED-001' });

    const diags = findingsToDiagnostics([finding], doc);

    assert.ok(diags[0].message.includes('mcp-audit: Fix current file'));
  });

  test('non-auto-fixable finding does not include fix hint', async () => {
    const doc = await makeDocument(
      JSON.stringify({ mcpServers: { 'test-server': {} } })
    );
    const finding = makeFinding({ id: 'POISON-001' });

    const diags = findingsToDiagnostics([finding], doc);

    assert.ok(!diags[0].message.includes('mcp-audit: Fix current file'));
  });

  test('test_malformed_json_config — makeMalformedJsonDiagnostic produces error at line 0', async () => {
    const doc = await makeDocument('{invalid json}');
    const diag = makeMalformedJsonDiagnostic(doc);

    assert.strictEqual(diag.severity, vscode.DiagnosticSeverity.Error);
    assert.ok(diag.message.includes('not valid JSON'));
    assert.strictEqual(diag.range.start.line, 0);
  });
});

suite('diagnostics — mapSeverity()', () => {
  test('test_severity_mapping — CRITICAL maps to Error', () => {
    assert.strictEqual(
      mapSeverity('CRITICAL'),
      vscode.DiagnosticSeverity.Error
    );
  });

  test('test_severity_mapping — HIGH maps to Error', () => {
    assert.strictEqual(mapSeverity('HIGH'), vscode.DiagnosticSeverity.Error);
  });

  test('test_severity_mapping — MEDIUM maps to Warning', () => {
    assert.strictEqual(
      mapSeverity('MEDIUM'),
      vscode.DiagnosticSeverity.Warning
    );
  });

  test('test_severity_mapping — LOW maps to Information', () => {
    assert.strictEqual(
      mapSeverity('LOW'),
      vscode.DiagnosticSeverity.Information
    );
  });

  test('test_severity_mapping — INFO maps to Hint', () => {
    assert.strictEqual(mapSeverity('INFO'), vscode.DiagnosticSeverity.Hint);
  });
});
