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
