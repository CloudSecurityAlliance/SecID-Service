// ── SecID Types ──
// Valid SecID types are defined by the type-registry (single source of truth).
// Re-exported here so existing imports of `SECID_TYPES`/`SecIDType` from
// "./types" keep working without churn across the codebase.
import { SECID_TYPES as _SECID_TYPES, type SecIDType as _SecIDType } from "./type-registry";
export const SECID_TYPES = _SECID_TYPES;
export type SecIDType = _SecIDType;

// ── Parsed SecID ──
// Result of parsing a SecID string into components
export interface ParsedSecID {
  raw: string; // Original input, verbatim
  prefix: boolean; // Had "secid:" prefix
  type: SecIDType | null;
  namespace: string | null; // "mitre.org", "github.com/advisories"
  name: string | null; // Matched match_node name (e.g., "cve", "attack")
  version: string | null; // @version after name
  subpath: string | null; // Everything after #
  itemVersion: string | null; // @version after subpath item (future)
  qualifiers: Record<string, string> | null; // ?key=value pairs
}

// ── Registry Data Structures ──
// Mirrors the JSON schema from REGISTRY-JSON-FORMAT.md

export interface RegistryUrl {
  type: string; // "website", "docs", "api", "bulk_data", "lookup", "security", "paper", ...
  url: string;
  format?: string; // Expected content format: "html", "json", "pdf", "xml", "csv"
  note?: string; // Human/AI readable context
  lang?: string; // ISO 639-1 language code
}

export interface ExampleObject {
  input: string;
  variables?: Record<string, string>;
  url?: string;
  version?: string;
  note?: string;
}

export interface VariableDefinition {
  extract: string; // Regex with capture group
  format?: string; // Template like "{1}xxx"
  lookup?: string; // "range_table" or other lookup type
  description?: string;
}

export interface LookupTableEntry {
  url: string;
  title?: string;
}

export interface LangConfig {
  available: string[];       // ISO 639-1 codes: ["en", "de", "fr", ...]
  default: string;           // Default language code (e.g., "en")
  url_transform?: string;    // "uppercase" → "EN", null/absent → as-is
}

export interface MatchNodeData {
  // Source-level fields
  official_name?: string;
  common_name?: string | null;
  alternate_names?: string[] | null;
  description?: string;
  notes?: string;
  urls?: RegistryUrl[];
  examples?: (string | ExampleObject)[];

  // Child-level fields
  url?: string;
  format?: string;
  content_type?: string; // MIME type from HTTP Content-Type header
  parsability?: string;  // "structured" or "scraped"
  schema?: string;       // SecID reference to data schema
  parsing_instructions?: string; // SecID reference to parsing instruction doc
  auth?: string;         // Free-text auth description
  lang?: LangConfig;     // Language availability and URL substitution config
  type?: string;
  note?: string;
  /**
   * Enumeration of the identifiers this node accepts, id → title. Treated as a
   * closed set only when `patterns` is open (see isOpenPattern) — several
   * registry entries pair a tight pattern with a deliberately partial list.
   */
  known_values?: Record<string, string>;
  variables?: Record<string, VariableDefinition>;
  lookup_table?: Record<string, string | LookupTableEntry>;

  // Version fields (source-level)
  version_required?: boolean;
  unversioned_behavior?: string;
  version_disambiguation?: string;
  versions_available?: VersionInfo[];

  // Provenance
  provenance?: {
    method?: string;
    date?: string;
    source_url?: string;
  };
}

export interface VersionInfo {
  version: string;
  release_date?: string;
  status?: string;
  note?: string;
}

export interface MatchNode {
  patterns: string[]; // Regex patterns to match against
  description: string;
  weight: number;
  data: MatchNodeData;
  children?: MatchNode[];
  /**
   * The registry declaring that this identifier space is genuinely unbounded
   * (GitHub usernames, Jira project keys, conference paper slugs) and the
   * permissive pattern is intentional. Such nodes are excluded from unscoped
   * cross-source search — an unbounded pattern cannot tell a real identifier
   * from an arbitrary search term — while namespace-scoped resolution still
   * works. Absent means "expected to discriminate"; see
   * scripts/check-pattern-breadth.py in the SecID repo, which fails an
   * undeclared open pattern.
   */
  open_pattern?: boolean;
}

export interface RegistryNamespace {
  schema_version: string;
  namespace: string;
  type: SecIDType;
  status: string;
  status_notes: string | null;

  official_name: string;
  common_name: string | null;
  alternate_names: string[] | null;
  notes: string | null;
  wikidata: string | null;
  wikipedia: string | null;

  urls: RegistryUrl[];
  match_nodes: MatchNode[];
}

// The compiled registry: type → namespace → data
export type Registry = Record<string, Record<string, RegistryNamespace>>;

// ── KV Registry Types ──
// Used by kv-registry.ts and upload-registry-kv.ts

export interface TypeIndex {
  type: string;
  description: string;
  purpose?: string;
  format?: string;
  examples?: string[];
  notes?: string;
  namespace_count: number;
  namespaces: Array<{
    namespace: string;
    official_name: string;
    common_name: string | null;
    source_count: number;
    /** Union of subtype values across all source-level match_nodes in this
     *  namespace (e.g., ["mapping", "scoring"]). Empty array means no
     *  subtype tags. Older deploys may omit this field; treat absent as
     *  empty for filter purposes. */
    subtypes?: string[];
    /** ISO 3166-1 alpha-2 codes from the namespace's tags.country (plus EU /
     *  INTL). Absent means untagged, which is NOT the same as "no country" —
     *  most .com and .org namespaces simply have not been curated, so a filter
     *  must exclude them rather than guess. */
    country?: string[];
  }>;
  child_index: ChildIndexEntry[];
}

export interface ChildIndexEntry {
  namespace: string;
  name_slug: string;
  /**
   * "source" entries match the source-level match_node itself (e.g., "cwe"
   * matches weakness/mitre.org/cwe). "child" entries match a specific item
   * identifier within a source (e.g., "CVE-2021-44228" matches a child of
   * advisory/mitre.org/cve). Older deploys may omit this field; treat
   * absent as "child" for backward compatibility.
   */
  level?: "source" | "child";
  patterns: string[];
  description: string;
  weight: number;
  has_url: boolean;
}

// Combined child_index across all types, stored under KV key "secid:*"
export interface GlobalChildIndexEntry extends ChildIndexEntry {
  /**
   * This node accepts arbitrary input — declared via open_pattern or detected
   * from the regex. Bare-identifier search skips these: an unbounded pattern
   * cannot tell a real identifier from a search term. Absent on deploys
   * predating this field, so callers must fall back to detection.
   */
  open?: boolean;
  type: SecIDType;
}

/**
 * Namespace identity entry — lets free-text search find a namespace by the name
 * people actually type (its domain label or declared names) rather than only by
 * a source slug. `aliases` are pre-lowercased for exact comparison.
 */
export interface NameIndexEntry {
  type: string;
  namespace: string;
  aliases: string[];
}

export interface GlobalIndex {
  child_index: GlobalChildIndexEntry[];
  /** Absent on deploys predating identity search — callers must tolerate that. */
  name_index?: NameIndexEntry[];
}

export interface RegistryMeta {
  version: string;
  total_namespaces: number;
  types: Record<string, number>;
}

/**
 * Per-type subtype counts. Outer key is type name, inner key is subtype value,
 * value is the number of source-level match_nodes carrying that subtype.
 * Populated at KV upload time by walking registry entries; served via /api/v1/types.
 */
export type SubtypeCounts = Record<string, Record<string, number>>;

// ── App Environment ──
// Cloudflare Worker bindings available via Hono context
export interface AppBindings {
  secid_OBSERVABILITY?: KVNamespace;
  secid_REGISTRY?: KVNamespace;
  secid_FEEDBACK?: KVNamespace;
}

export type AppEnv = {
  Bindings: AppBindings;
};

// ── API Response Types ──
// Per API-RESPONSE-FORMAT.md

export type ResponseStatus =
  | "found"
  | "corrected"
  | "related"
  | "not_found"
  | "error";

export interface ResolutionResult {
  secid: string;
  weight: number;
  url: string;
  content_type?: string; // MIME type of the resource at the URL
  lang?: string;         // Language code of the resolved result
  parsability?: string;  // "structured" or "scraped"
  schema?: string;       // SecID reference to data schema
  parsing_instructions?: string; // SecID reference to parsing instruction doc
  auth?: string;         // Free-text auth description
}

export interface RegistryResult {
  secid: string;
  data: Record<string, unknown>;
}

export type ResultEntry = ResolutionResult | RegistryResult;

export interface ResolveResponse {
  secid_query: string;
  status: ResponseStatus;
  results: ResultEntry[];
  message?: string;
}

// Type guard helpers
export function isResolutionResult(r: ResultEntry): r is ResolutionResult {
  return "url" in r && "weight" in r;
}

export function isRegistryResult(r: ResultEntry): r is RegistryResult {
  return "data" in r && !("url" in r);
}
