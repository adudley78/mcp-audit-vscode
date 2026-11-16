/**
 * Status bar item showing the current file's Credenzo grade and finding count.
 *
 * Examples:
 *   Credenzo: A (0 findings)
 *   Credenzo: C (5 findings)
 *   Credenzo: scanning…
 *   Credenzo: ✗ binary not found
 */

import * as vscode from 'vscode';
import { STATUS_BAR_COMMAND } from './constants';

export class McpAuditStatusBar {
  private readonly _item: vscode.StatusBarItem;

  constructor() {
    this._item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      // Priority 100 keeps it to the left of most items.
      100
    );
    this._item.command = STATUS_BAR_COMMAND;
    this._item.name = 'Credenzo';
  }

  showScanning(): void {
    this._item.text = '$(sync~spin) Credenzo: scanning…';
    this._item.tooltip = 'Credenzo is scanning this file';
    this._item.backgroundColor = undefined;
    this._item.show();
  }

  showResult(grade: string, findingCount: number): void {
    this._item.text = `$(shield) Credenzo: ${grade} (${findingCount} finding${findingCount === 1 ? '' : 's'})`;
    this._item.tooltip = `Credenzo grade: ${grade} — click to open Problems panel`;
    this._item.backgroundColor =
      findingCount > 0
        ? new vscode.ThemeColor('statusBarItem.warningBackground')
        : undefined;
    this._item.show();
  }

  showNoBinary(): void {
    this._item.text = '$(shield) Credenzo: ✗ binary not found';
    this._item.tooltip =
      'Credenzo binary not found — see the extension README for install instructions';
    this._item.backgroundColor = new vscode.ThemeColor(
      'statusBarItem.errorBackground'
    );
    this._item.show();
  }

  hide(): void {
    this._item.hide();
  }

  dispose(): void {
    this._item.dispose();
  }
}
