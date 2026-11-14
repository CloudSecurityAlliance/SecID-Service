/**
 * MCP tool contract hashing and differential change log (#44).
 *
 * Pilot implementation of two complementary primitives so MCP clients and
 * agent harnesses can detect tool changes without re-diffing full schemas on
 * every session:
 *
 *   1. Per-tool `_meta` in `tools/list`:
 *      - `io.cloudsecurityalliance.secid/contractHash`: `"sha256:<hex>"` over
 *        the RFC 8785 JCS canonical JSON of `{ name, description, inputSchema, annotations }`.
 *      - `io.cloudsecurityalliance.secid/changed`: RFC 3339 timestamp of the
 *        most recent change to that tool's contract or behavior.
 *
 *   2. `describe_changes` MCP tool:
 *      - Accepts optional `since` (RFC 3339 timestamp).
 *      - Returns `{ toolset_hash, last_changed, since, tools, changes }` with
 *        structured change entries strictly newer than `since` (or the full
 *        history when `since` is omitted).
 */

import {
  normalizeObjectSchema,
  type AnySchema,
  type ZodRawShapeCompat,
} from "@modelcontextprotocol/sdk/server/zod-compat.js";
import { toJsonSchemaCompat } from "@modelcontextprotocol/sdk/server/zod-json-schema-compat.js";

export const CONTRACT_HASH_META_KEY = "io.cloudsecurityalliance.secid/contractHash";
export const CHANGED_META_KEY = "io.cloudsecurityalliance.secid/changed";

export type ToolChangeType = "added" | "updated" | "deprecated" | "removed";

export interface ToolChangeEntry {
  timestamp: string;
  tool: string;
  change_type: ToolChangeType;
  summary: string;
  contract_hash?: string;
}

export interface ToolContractInput {
  name: string;
  description: string;
  inputSchema?: ZodRawShapeCompat | AnySchema;
  annotations?: Record<string, unknown>;
}

export interface ToolContractSummary {
  contract_hash: string;
  changed: string;
}

export interface ToolContractManifest {
  toolset_hash: string;
  last_changed: string;
  tools: Record<string, ToolContractSummary>;
  metaByTool: Record<string, Record<string, string>>;
  changes: ToolChangeEntry[];
}

export interface DescribeChangesResponse {
  toolset_hash: string;
  last_changed: string;
  since: string | null;
  tools: Record<string, ToolContractSummary>;
  changes: ToolChangeEntry[];
}

export class InvalidSinceTimestampError extends Error {
  constructor(since: string) {
    super(
      `Invalid 'since' timestamp '${since}': must be an RFC 3339 / ISO 8601 timestamp (e.g. '2026-04-01T00:00:00Z').`
    );
    this.name = "InvalidSinceTimestampError";
  }
}

const EMPTY_OBJECT_JSON_SCHEMA: Record<string, unknown> = {
  type: "object",
  properties: {},
};

const RFC3339_OR_ISO_DATE_RE =
  /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$/;

/**
 * Historical change log for SecID MCP tools, ordered newest-first.
 *
 * Each registered tool's `io.cloudsecurityalliance.secid/changed` timestamp is
 * derived from its newest entry in this log so `_meta` and `describe_changes`
 * never drift.
 */
export const TOOL_CHANGE_LOG: readonly ToolChangeEntry[] = [
  {
    timestamp: "2026-11-14T00:00:00Z",
    tool: "resolve",
    change_type: "updated",
    summary:
      "MCP output sanitizer switched from a deny-list of prose keys to an allow-list of structural keys. Every other registry field, at any depth, now moves under registry_text_untrusted: only structural keys stay in place (secid, url, weight, pattern, type, status, format, lang, content_type, parsability, schema, version, label, input, examples, available_items, versions_available, aliases, namespace(s), subtype(s), country, release_date, checked, wikidata, wikipedia, version_required, the counts, and the data/urls/patterns containers). Fields that moved include capability audit/configure commands, vendor_recommendation, options, default, cross_references, known_values, variables, lookup_table, cve, security_txt and internal _-prefixed notes. A structural key whose value does not look structural also moves (a url that is not http(s), an identifier over 128 characters, or over 48 if it contains whitespace). Every string, the echoed secid_query and error envelopes included, is control-stripped; keys inside the envelope too; strings are capped at 4000 code points (#67).",
  },
  {
    timestamp: "2026-11-14T00:00:00Z",
    tool: "lookup",
    change_type: "updated",
    summary:
      "MCP output sanitizer switched from a deny-list of prose keys to an allow-list of structural keys. Every other registry field, at any depth, now moves under registry_text_untrusted: only structural keys stay in place (secid, url, weight, pattern, type, status, format, lang, content_type, parsability, schema, version, label, input, examples, available_items, versions_available, aliases, namespace(s), subtype(s), country, release_date, checked, wikidata, wikipedia, version_required, the counts, and the data/urls/patterns containers). Fields that moved include capability audit/configure commands, vendor_recommendation, options, default, cross_references, known_values, variables, lookup_table, cve, security_txt and internal _-prefixed notes. A structural key whose value does not look structural also moves (a url that is not http(s), an identifier over 128 characters, or over 48 if it contains whitespace). Every string, the echoed secid_query and error envelopes included, is control-stripped; keys inside the envelope too; strings are capped at 4000 code points (#67).",
  },
  {
    timestamp: "2026-11-14T00:00:00Z",
    tool: "describe",
    change_type: "updated",
    summary:
      "MCP output sanitizer switched from a deny-list of prose keys to an allow-list of structural keys. Every other registry field, at any depth, now moves under registry_text_untrusted: only structural keys stay in place (secid, url, weight, pattern, type, status, format, lang, content_type, parsability, schema, version, label, input, examples, available_items, versions_available, aliases, namespace(s), subtype(s), country, release_date, checked, wikidata, wikipedia, version_required, the counts, and the data/urls/patterns containers). Fields that moved include capability audit/configure commands, vendor_recommendation, options, default, cross_references, known_values, variables, lookup_table, cve, security_txt and internal _-prefixed notes. A structural key whose value does not look structural also moves (a url that is not http(s), an identifier over 128 characters, or over 48 if it contains whitespace). Every string, the echoed secid_query and error envelopes included, is control-stripped; keys inside the envelope too; strings are capped at 4000 code points (#67). "
      + "The secid://registry/<type> resources now carry official_name and common_name under registry_text_untrusted as well.",
  },
  {
    timestamp: "2026-11-14T00:00:00Z",
    tool: "submit_feedback",
    change_type: "updated",
    summary:
      "The secid echoed in the response is now control-stripped like every other MCP output string (#67).",
  },
  {
    timestamp: "2026-11-14T00:00:00Z",
    tool: "describe_changes",
    change_type: "updated",
    summary:
      "The invalid-'since' error message, which echoes the caller's input, is now control-stripped (#67). "
      + "Corrected the 2026-09-25 submit_feedback entry, which misstated the input limits.",
  },
  {
    timestamp: "2026-11-04T00:00:00Z",
    tool: "describe_changes",
    change_type: "added",
    summary:
      "Added describe_changes tool and per-tool _meta contract hashes (io.cloudsecurityalliance.secid/contractHash, io.cloudsecurityalliance.secid/changed) for cache invalidation and differential tool discovery (#44).",
  },
  {
    timestamp: "2026-11-04T00:00:00Z",
    tool: "describe",
    change_type: "updated",
    summary:
      "Namespace-level queries (secid:type/namespace) for namespaces with empty match_nodes (such as entity records) now return a single result with namespace-level metadata (official_name, common_name, alternate_names, notes, urls, wikidata, wikipedia, source_count: 0) instead of an empty results array (#11).",
  },
  {
    timestamp: "2026-11-04T00:00:00Z",
    tool: "resolve",
    change_type: "updated",
    summary:
      "Namespace-level queries (secid:type/namespace) for namespaces with empty match_nodes now return the namespace's own metadata record instead of an empty results array (#11).",
  },
  {
    timestamp: "2026-11-04T00:00:00Z",
    tool: "lookup",
    change_type: "updated",
    summary:
      "Namespace-level lookups (lookup(type, namespace)) for namespaces with empty match_nodes now return the namespace's own metadata record instead of an empty results array (#11).",
  },
  {
    timestamp: "2026-09-25T19:51:30Z",
    tool: "submit_feedback",
    change_type: "updated",
    summary:
      "Added input length bounds (secid max 1024 chars, message 1..4000 chars, suggested_urls max 10 entries of 2048 chars) and per-isolate write rate limiting (#38).",
  },
  {
    timestamp: "2026-06-22T16:32:32Z",
    tool: "resolve",
    change_type: "updated",
    summary:
      "Relocated contributor-authored free-text fields under registry_text_untrusted across the MCP output boundary and enforced a 1024-character query cap (#18).",
  },
  {
    timestamp: "2026-06-22T16:32:32Z",
    tool: "lookup",
    change_type: "updated",
    summary:
      "Relocated contributor-authored free-text fields under registry_text_untrusted across the MCP output boundary and enforced a 1024-character identifier cap (#18).",
  },
  {
    timestamp: "2026-06-22T16:32:32Z",
    tool: "describe",
    change_type: "updated",
    summary:
      "Relocated contributor-authored free-text fields under registry_text_untrusted across the MCP output boundary and enforced a 1024-character query cap (#18).",
  },
  {
    timestamp: "2026-06-20T03:57:04Z",
    tool: "submit_feedback",
    change_type: "added",
    summary:
      "Added submit_feedback tool (missing-namespace, correction, suggestion) as the MCP-only feedback intake channel (#16).",
  },
  {
    timestamp: "2026-05-21T13:44:08Z",
    tool: "lookup",
    change_type: "updated",
    summary:
      "Derived the 10-type enum (advisory, weakness, ttp, control, capability, methodology, disclosure, regulation, entity, reference) from the single-source TYPE_REGISTRY (#8).",
  },
  {
    timestamp: "2026-03-04T17:54:26Z",
    tool: "resolve",
    change_type: "added",
    summary: "Initial release of the resolve MCP tool.",
  },
  {
    timestamp: "2026-03-04T17:54:26Z",
    tool: "lookup",
    change_type: "added",
    summary: "Initial release of the lookup MCP tool.",
  },
  {
    timestamp: "2026-03-04T17:54:26Z",
    tool: "describe",
    change_type: "added",
    summary: "Initial release of the describe MCP tool.",
  },
];

/**
 * Serialize a JSON-compatible value into RFC 8785 (JCS) canonical form:
 *   - Object keys sorted lexicographically by UTF-16 code units
 *   - Object properties with `undefined` values omitted
 *   - Array order preserved
 *   - No insignificant whitespace
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalizeJson(item ?? null)).join(",") + "]";
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record)
    .filter((k) => record[k] !== undefined)
    .sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + canonicalizeJson(record[k]))
      .join(",") +
    "}"
  );
}

// ── Pure TypeScript SHA-256 (FIPS 180-4 / RFC 6234) ──
// Used at module initialization so tool contract hashes can be computed
// synchronously once per isolate without requiring nodejs_compat or async
// server construction. Verified against Web Crypto crypto.subtle.digest in tests.

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

export function sha256Hex(input: string): string {
  const bytes = new TextEncoder().encode(input);
  const bitLen = bytes.length * 8;
  const paddedLen = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  const highBits = Math.floor(bitLen / 0x100000000);
  const lowBits = bitLen >>> 0;
  view.setUint32(paddedLen - 8, highBits, false);
  view.setUint32(paddedLen - 4, lowBits, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((n) => n.toString(16).padStart(8, "0"))
    .join("");
}

/**
 * Convert a tool's Zod raw shape / schema into the exact JSON Schema object
 * that `@modelcontextprotocol/sdk`'s `McpServer` emits in `tools/list`.
 */
export function computeToolInputJsonSchema(
  inputSchema: ZodRawShapeCompat | AnySchema | undefined
): Record<string, unknown> {
  const obj = normalizeObjectSchema(inputSchema);
  return obj
    ? (toJsonSchemaCompat(obj, {
        strictUnions: true,
        pipeStrategy: "input",
      }) as Record<string, unknown>)
    : EMPTY_OBJECT_JSON_SCHEMA;
}

/**
 * Compute `sha256:<hex>` over the RFC 8785 JCS canonical JSON of a tool's
 * public contract (`{ name, description, inputSchema, annotations }`).
 */
export function computeToolContractHash(contract: {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}): string {
  const canonical = canonicalizeJson({
    name: contract.name,
    description: contract.description,
    inputSchema: contract.inputSchema,
    ...(contract.annotations !== undefined ? { annotations: contract.annotations } : {}),
  });
  return `sha256:${sha256Hex(canonical)}`;
}

/**
 * Build the complete contract manifest for all registered MCP tools.
 */
export function buildToolContractManifest(
  defs: ReadonlyArray<ToolContractInput>,
  changeLog: ReadonlyArray<ToolChangeEntry> = TOOL_CHANGE_LOG
): ToolContractManifest {
  const tools: Record<string, ToolContractSummary> = {};
  const metaByTool: Record<string, Record<string, string>> = {};
  const latestHashByTool: Record<string, string> = {};

  for (const def of defs) {
    const jsonSchema = computeToolInputJsonSchema(def.inputSchema);
    const contractHash = computeToolContractHash({
      name: def.name,
      description: def.description,
      inputSchema: jsonSchema,
      annotations: def.annotations,
    });

    const toolEntries = changeLog.filter((e) => e.tool === def.name);
    const latestChanged =
      toolEntries.reduce<string | null>((max, e) => {
        if (max === null || Date.parse(e.timestamp) > Date.parse(max)) {
          return e.timestamp;
        }
        return max;
      }, null) ?? "2026-03-04T00:00:00Z";

    tools[def.name] = {
      contract_hash: contractHash,
      changed: latestChanged,
    };
    metaByTool[def.name] = {
      [CONTRACT_HASH_META_KEY]: contractHash,
      [CHANGED_META_KEY]: latestChanged,
    };
    latestHashByTool[def.name] = contractHash;
  }

  const toolsetHash = `sha256:${sha256Hex(canonicalizeJson(latestHashByTool))}`;

  const lastChanged =
    changeLog.reduce<string | null>((max, e) => {
      if (max === null || Date.parse(e.timestamp) > Date.parse(max)) {
        return e.timestamp;
      }
      return max;
    }, null) ?? "2026-03-04T00:00:00Z";

  // Attach the current contract_hash to the most recent change entry for each tool.
  const seenLatestForTool = new Set<string>();
  const annotatedChanges: ToolChangeEntry[] = [...changeLog]
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
    .map((entry) => {
      if (!seenLatestForTool.has(entry.tool) && latestHashByTool[entry.tool]) {
        seenLatestForTool.add(entry.tool);
        return {
          ...entry,
          contract_hash: latestHashByTool[entry.tool],
        };
      }
      return { ...entry };
    });

  return {
    toolset_hash: toolsetHash,
    last_changed: lastChanged,
    tools,
    metaByTool,
    changes: annotatedChanges,
  };
}

/**
 * Evaluate `describe_changes` for an optional `since` RFC 3339 / ISO 8601 timestamp.
 */
export function describeToolChanges(
  manifest: ToolContractManifest,
  since?: string
): DescribeChangesResponse {
  if (since === undefined) {
    return {
      toolset_hash: manifest.toolset_hash,
      last_changed: manifest.last_changed,
      since: null,
      tools: manifest.tools,
      changes: manifest.changes,
    };
  }

  const trimmed = since.trim();
  if (!RFC3339_OR_ISO_DATE_RE.test(trimmed)) {
    throw new InvalidSinceTimestampError(since);
  }
  const sinceMs = Date.parse(trimmed);
  if (Number.isNaN(sinceMs)) {
    throw new InvalidSinceTimestampError(since);
  }

  const filtered = manifest.changes.filter((entry) => Date.parse(entry.timestamp) > sinceMs);
  return {
    toolset_hash: manifest.toolset_hash,
    last_changed: manifest.last_changed,
    since: trimmed,
    tools: manifest.tools,
    changes: filtered,
  };
}
