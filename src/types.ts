/**
 * TypeScript mirror of the mcp-audit Python models.
 * Keep in sync with src/mcp_audit/models.py in the mcp-audit repo.
 * JSON key names match the serialised output (aliases applied by Pydantic).
 */

export type McpSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Finding {
  id: string;
  severity: McpSeverity;
  analyzer: string;
  /** MCP client name (e.g. "Claude Desktop") */
  client: string;
  /** Server key in the MCP config (e.g. "filesystem") */
  server: string;
  tool: string | null;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cwe: string | null;
  finding_path: string | null;
  owasp_mcp_top_10: string[];
  cve: string[];
}

export interface ScanScore {
  /** JSON serialisation alias: "numeric" */
  numeric: number;
  grade: string;
  positive_signals: string[];
  deductions: string[];
}

export interface ScanResult {
  version: string;
  timestamp: string;
  findings: Finding[];
  score: ScanScore | null;
  errors: string[];
}

// ── mcp-audit vet (>= 1.1.0) ────────────────────────────────────────────────

/**
 * Single-server result returned by `mcp-audit vet <name> --format json`.
 * Mirrors the Python VetResult model. Keep in sync with mcp-audit models.py.
 */
export interface VetResult {
  /** Server / package name that was looked up. */
  name: string;
  /** Registry verdict for this package. */
  verdict: 'verified' | 'cve' | 'typosquat' | 'unknown';
  /** Total number of known CVEs (0 when verdict is not 'cve'). */
  cve_count: number;
  /** CVE identifiers, e.g. ["CVE-2024-1234"]. */
  cve_ids: string[];
  /** Short human-readable capabilities description, or null if not in registry. */
  capabilities: string | null;
  /** Likely-intended package name when verdict is 'typosquat', else null. */
  typosquat_suggestion: string | null;
  /** Canonical mcp-audit.dev URL for this package, or null. */
  registry_url: string | null;
  /** Maintainer / publisher name, or null. */
  maintainer: string | null;
}

/** Result of feature-detecting the `vet` subcommand on the installed binary. */
export interface VetSupportInfo {
  /** True when `mcp-audit vet --help` exits 0 or 1 and mentions "vet". */
  supported: boolean;
  /** True when the help text indicates multiple names are accepted at once. */
  supportsBatch: boolean;
}
