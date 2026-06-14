/**
 * Shared constants for file matching and configuration.
 */

/**
 * File glob patterns whose matching documents should be scanned.
 * VS Code evaluates these patterns against the document's file name only
 * when used as a language selector, so we also check by basename in
 * `isMcpConfigFile()`.
 */
export const MCP_FILE_PATTERNS = [
  'claude_desktop_config.json',
  'mcp.json',
  'claude_code_config.json',
  'mcp_config.json',
  'claude_settings.json',
] as const;

/**
 * Path segment patterns: a file is an MCP config when its basename is in
 * MCP_FILE_PATTERNS, OR when its path matches one of these suffixes.
 */
export const MCP_PATH_SUFFIXES = [
  '.cursor/mcp.json',
  '.claude/settings.json',
] as const;

/** Diagnostic collection identifier shown in the Problems panel source column. */
export const DIAGNOSTIC_SOURCE = 'mcp-audit';

/** Output channel name shown in View → Output. */
export const OUTPUT_CHANNEL_NAME = 'mcp-audit';

/** Status bar item command (opens the Problems panel). */
export const STATUS_BAR_COMMAND = 'workbench.actions.view.problems';

/** Maximum file size in bytes to scan (5 MB). */
export const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024;

/** Timeout for a single scan subprocess in milliseconds. */
export const SCAN_TIMEOUT_MS = 10_000;

/** Timeout for a single `mcp-audit vet` subprocess in milliseconds. */
export const VET_TIMEOUT_MS = 8_000;

/** Debounce delay before firing a vet run after a document event (ms). */
export const VERDICT_DEBOUNCE_MS = 300;

/** DiagnosticCollection source identifier for registry verdicts. */
export const VERDICT_DIAGNOSTIC_SOURCE = 'mcp-audit-vet';

/** Root keys tried when resolving server positions in a config JSON. */
export const MCP_JSON_ROOT_KEYS = ['mcpServers', 'servers'] as const;

/**
 * Finding IDs for which `mcp-audit fix --apply` has an automated remedy.
 * Used in hover card messaging.
 */
export const AUTO_FIXABLE_IDS = new Set([
  'CRED-001',
  'CRED-002',
  'TRANSPORT-001',
  'SC-001',
  'SC-002',
]);
