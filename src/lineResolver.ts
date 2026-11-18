/**
 * Resolve the VS Code document range for a named MCP server key.
 *
 * Strategy:
 *  1. Parse the document text with jsonc-parser (handles comments / trailing
 *     commas that VS Code config files sometimes contain).
 *  2. Walk the object tree under "mcpServers" or "servers" to find the
 *     property whose key matches `serverName`.
 *  3. Return a Range spanning the key string so the squiggle underlines the
 *     server name token.
 *  4. On any failure (malformed JSON, server key absent) fall back to line 0
 *     so the diagnostic is still surfaced at the top of the file.
 *
 * Known limitation: the Credenzo `Finding` model does not yet carry
 * line/column information, so we infer position from the server name alone.
 * A follow-up story (Finding.line_number) will allow exact finding-level
 * precision when available.
 */

import * as jsonc from 'jsonc-parser';
import * as vscode from 'vscode';
import { MCP_JSON_ROOT_KEYS } from './constants';

/** One server entry: its key, the range of the key, and its launch command. */
export interface ServerEntry {
  name: string;
  range: vscode.Range;
  /** The `command` value as written (not checked). */
  command?: unknown;
  /** The `args` value as written (not checked). */
  args?: unknown;
}

/**
 * Return every server name + its key range + its launch command from
 * `mcpServers` / `servers`. VerdictProvider finds the package of each server
 * from `command` and `args`.
 * Returns an empty array if the document has no server entries or is
 * malformed.
 */
export function resolveAllServers(
  document: vscode.TextDocument
): ServerEntry[] {
  const results: ServerEntry[] = [];
  try {
    const text = document.getText();
    const root = jsonc.parseTree(text);
    if (!root || root.type !== 'object' || !root.children) return results;

    for (const rootKey of MCP_JSON_ROOT_KEYS) {
      const serversNode = jsonc.findNodeAtLocation(root, [rootKey]);
      if (
        !serversNode ||
        serversNode.type !== 'object' ||
        !serversNode.children
      ) {
        continue;
      }

      for (const prop of serversNode.children) {
        if (
          prop.type !== 'property' ||
          !prop.children ||
          prop.children.length < 2
        ) {
          continue;
        }
        const keyNode = prop.children[0];
        const name = keyNode.value as string;
        if (typeof name !== 'string' || !name) continue;

        const start = document.positionAt(keyNode.offset);
        const end = document.positionAt(keyNode.offset + keyNode.length);
        const valueNode = prop.children[1];
        const entry: ServerEntry = { name, range: new vscode.Range(start, end) };
        if (valueNode.type === 'object') {
          const commandNode = jsonc.findNodeAtLocation(valueNode, ['command']);
          const argsNode = jsonc.findNodeAtLocation(valueNode, ['args']);
          if (commandNode) entry.command = jsonc.getNodeValue(commandNode);
          if (argsNode) entry.args = jsonc.getNodeValue(argsNode);
        }
        results.push(entry);
      }
    }
  } catch {
    // Parse error — return whatever was collected so far.
  }
  return results;
}

/**
 * Return the document `Range` that covers the key token for `serverName`
 * within the `mcpServers` / `servers` block.
 *
 * Falls back to the first line of the document if the key cannot be located.
 */
export function resolveServerRange(
  document: vscode.TextDocument,
  serverName: string
): vscode.Range {
  try {
    const text = document.getText();
    const root = jsonc.parseTree(text);
    if (!root || root.type !== 'object' || !root.children) {
      return document.lineAt(0).range;
    }

    for (const rootKey of MCP_JSON_ROOT_KEYS) {
      const serversNode = jsonc.findNodeAtLocation(root, [rootKey]);
      if (
        !serversNode ||
        serversNode.type !== 'object' ||
        !serversNode.children
      ) {
        continue;
      }

      for (const prop of serversNode.children) {
        // Each child of an object node is a property node:
        //   children[0] = key (string node whose .value is the key text)
        //   children[1] = value node
        if (
          prop.type !== 'property' ||
          !prop.children ||
          prop.children.length < 2
        ) {
          continue;
        }
        const keyNode = prop.children[0];
        if (keyNode.value === serverName) {
          const start = document.positionAt(keyNode.offset);
          const end = document.positionAt(keyNode.offset + keyNode.length);
          return new vscode.Range(start, end);
        }
      }
    }
  } catch {
    // Any parse error — fall through to the top-of-file range.
  }

  return document.lineAt(0).range;
}
