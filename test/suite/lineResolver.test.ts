/**
 * Unit tests for resolveServerRange().
 * Verifies that the line resolver correctly locates server keys in both
 * mcpServers and servers root formats, and falls back gracefully.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { resolveServerRange } from '../../src/lineResolver';

async function makeDoc(content: string): Promise<vscode.TextDocument> {
  return vscode.workspace.openTextDocument({ content, language: 'json' });
}

suite('lineResolver — resolveServerRange()', () => {
  test('finds server key under mcpServers', async () => {
    const json = JSON.stringify(
      {
        mcpServers: {
          filesystem: { command: 'node', args: [] },
          fetch: { command: 'python', args: [] },
        },
      },
      null,
      2
    );
    const doc = await makeDoc(json);

    const range = resolveServerRange(doc, 'filesystem');

    assert.ok(range.start.line > 0, 'Should resolve past line 0');
    const lineText = doc.lineAt(range.start.line).text;
    assert.ok(lineText.includes('filesystem'));
  });

  test('finds server key under servers (VS Code format)', async () => {
    const json = JSON.stringify(
      {
        servers: {
          'my-server': { command: 'node', args: [] },
        },
      },
      null,
      2
    );
    const doc = await makeDoc(json);

    const range = resolveServerRange(doc, 'my-server');

    assert.ok(range.start.line > 0);
    assert.ok(doc.lineAt(range.start.line).text.includes('my-server'));
  });

  test('falls back to line 0 when server key is absent', async () => {
    const json = JSON.stringify({ mcpServers: {} });
    const doc = await makeDoc(json);

    const range = resolveServerRange(doc, 'nonexistent-server');

    assert.strictEqual(range.start.line, 0);
  });

  test('falls back to line 0 for completely malformed JSON', async () => {
    const doc = await makeDoc('{{{not valid');

    const range = resolveServerRange(doc, 'any-server');

    assert.strictEqual(range.start.line, 0);
  });

  test('falls back to line 0 for empty document', async () => {
    const doc = await makeDoc('');

    const range = resolveServerRange(doc, 'server');

    assert.strictEqual(range.start.line, 0);
  });
});
