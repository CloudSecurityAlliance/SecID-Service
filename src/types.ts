// ── SecID Types ──
// Valid SecID types as defined by the spec
export const SECID_TYPES = [
  "advisory",
  "weakness",
  "ttp",
  "control",
  "regulation",
  "entity",
  "reference",
] as const;

export type SecIDType = (typeof SECID_TYPES)[number];

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
  type: string; // "website", "api", "bulk_data", "lookup"
  url: string;
  format?: string;
  note?: string;
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
  lang?: LangConfig;     // Language availability and URL substitution config
  type?: string;
  note?: string;
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

// ── App Environment ──
// Cloudflare Worker bindings available via Hono context
export interface AppBindings {
  secid_OBSERVABILITY?: KVNamespace;
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
