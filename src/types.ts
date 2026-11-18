/**
 * TypeScript mirror of the Credenzo Python models.
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

// ── credenzo vet ───────────────────────────────────────────────────────────

/**
 * What the extension shows for one package. `verdictAdapter.ts` makes it from
 * the answer of `credenzo vet <package> --format json` (schema 1.x). The
 * command does not give these fields itself.
 */
export interface VetResult {
  /** Package name that the command looked up. */
  name: string;
  /**
   * malicious: an OSV MAL record names the pinned version or covers each
   *   release, or (no pin) has a range with no end.
   * cve: a recorded CVE affects the pinned version, or has no fix.
   * typosquat: the name is close to a registry name.
   * archived: the registry says that the package is not maintained.
   * verified / listed: in the registry, verified or not.
   * unknown: not in the registry.
   */
  verdict:
    | 'malicious'
    | 'cve'
    | 'typosquat'
    | 'archived'
    | 'verified'
    | 'listed'
    | 'unknown';
  /** Number of CVEs that affect the pinned version, or that have no fix (no pin). */
  cve_count: number;
  /** Number of CVEs that the command could not compare with the pinned version. */
  unchecked_cve_count: number;
  /** IDs of those CVEs, or the MAL record IDs when the verdict is malicious. */
  cve_ids: string[];
  /** Number of recorded CVEs that are not open (fixed). */
  fixed_cve_count: number;
  /**
   * IDs of MAL records that can cover this release, where the document does
   * not let the extension decide: no pin and a record that names releases, or
   * a pin and a record with a version range. A Warning, not the verdict.
   */
  possible_malicious_ids: string[];
  /**
   * IDs of MAL records that name releases, none of them the pinned version.
   * A note, not the verdict.
   */
  other_malicious_ids: string[];
  /** True when the registry says that the package is archived. */
  archived: boolean;
  /** The package that the registry names in its place, or null. */
  successor: string | null;
  /** True when the config entry pins an exact version and the command judged it. */
  pinned: boolean;
  /** Declared capabilities as one line, or null. */
  capabilities: string | null;
  /** The registry name that this name is close to, else null. */
  typosquat_suggestion: string | null;
  /** The page of the package on credenzo.io, or null when it has none. */
  registry_url: string | null;
  /** Maintainer, or null. */
  maintainer: string | null;
}

/** Result of feature-detecting the `vet` subcommand on the installed binary. */
export interface VetSupportInfo {
  /** True when `credenzo vet --help` exits 0 or 1 and has --ecosystem and --format. */
  supported: boolean;
}
