import { SECID_TYPES, type ParsedSecID, type Registry, type SecIDType } from "./types";

/**
 * Parse a SecID string into its components.
 *
 * Namespace resolution requires registry access — the parser tries
 * progressively longer candidates (shortest-to-longest) against
 * registry keys to find the longest matching namespace.
 */
export function parseSecID(input: string, registry: Registry): ParsedSecID {
  const result: ParsedSecID = {
    raw: input,
    prefix: false,
    type: null,
    namespace: null,
    name: null,
    version: null,
    subpath: null,
    itemVersion: null,
    qualifiers: null,
  };

  if (!input || typeof input !== "string") {
    return result;
  }

  let remaining = input.trim();

  // 1. Strip "secid:" prefix (case-insensitive)
  const prefixMatch = remaining.match(/^secid:/i);
  if (prefixMatch) {
    result.prefix = true;
    remaining = remaining.slice(prefixMatch[0].length);
  }

  if (!remaining) {
    return result;
  }

  // 2. Split at first # → head and subpath
  const hashIdx = remaining.indexOf("#");
  let head: string;
  let itemQualifiers: Record<string, string> | null = null;
  if (hashIdx !== -1) {
    head = remaining.slice(0, hashIdx);
    let rawSubpath = remaining.slice(hashIdx + 1) || null;
    // Strip ?qualifiers from subpath before pattern matching
    if (rawSubpath) {
      const qIdx = rawSubpath.indexOf("?");
      if (qIdx !== -1) {
        itemQualifiers = parseQualifiers(rawSubpath.slice(qIdx + 1));
        rawSubpath = rawSubpath.slice(0, qIdx) || null;
      }
    }
    result.subpath = rawSubpath;
  } else {
    head = remaining;
  }

  if (!head) {
    return result;
  }

  // 3. Extract type (first segment before /)
  const firstSlash = head.indexOf("/");
  const typeCandidate = firstSlash === -1 ? head : head.slice(0, firstSlash);
  const typeLower = typeCandidate.toLowerCase();

  if (!SECID_TYPES.includes(typeLower as SecIDType)) {
    // Invalid type — return with type=null
    return result;
  }

  result.type = typeLower as SecIDType;

  // Nothing after the type?
  if (firstSlash === -1) {
    return result;
  }

  remaining = head.slice(firstSlash + 1);
  if (!remaining) {
    return result;
  }

  // Strip source-level ?qualifiers before namespace resolution
  let sourceQualifiers: Record<string, string> | null = null;
  const headQIdx = remaining.indexOf("?");
  if (headQIdx !== -1) {
    sourceQualifiers = parseQualifiers(remaining.slice(headQIdx + 1));
    remaining = remaining.slice(0, headQIdx);
  }

  // 4. Namespace resolution (shortest-to-longest matching)
  const segments = remaining.split("/");
  const typeRegistry = registry[result.type] ?? {};

  let longestMatch: string | null = null;
  let matchLength = 0;

  // Build progressively longer candidates
  for (let i = 1; i <= segments.length; i++) {
    const candidate = segments.slice(0, i).join("/");
    if (candidate in typeRegistry) {
      longestMatch = candidate;
      matchLength = i;
    }
  }

  if (longestMatch) {
    result.namespace = longestMatch;

    // Everything after the namespace is name (possibly with @version)
    const afterNamespace = segments.slice(matchLength).join("/");
    if (afterNamespace) {
      extractNameAndVersion(afterNamespace, result);
    }
  } else {
    // No namespace found — the first segment might look like a domain
    // (contains '.') or it might be an identifier for cross-source search.
    // Store remaining as-is for the resolver to handle.
    const firstSeg = segments[0];
    if (firstSeg.includes(".")) {
      // Looks like a domain but not in registry — set namespace, parse rest
      result.namespace = firstSeg;
      const afterDomain = segments.slice(1).join("/");
      if (afterDomain) {
        extractNameAndVersion(afterDomain, result);
      }
    } else {
      // No domain-like segment — entire remaining is treated as name
      // (cross-source search scenario, e.g., "advisory/CVE-2024-1234")
      extractNameAndVersion(remaining, result);
    }
  }

  // Merge qualifiers (item-level takes precedence over source-level)
  if (sourceQualifiers || itemQualifiers) {
    result.qualifiers = { ...sourceQualifiers, ...itemQualifiers };
  }

  return result;
}

/**
 * Parse ?key=value&key2=value2 into a Record. Keys lowercased, values preserve case.
 */
function parseQualifiers(raw: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const pair of raw.split("&")) {
    const eqIdx = pair.indexOf("=");
    if (eqIdx === -1) continue;
    const key = pair.slice(0, eqIdx).toLowerCase();
    const value = pair.slice(eqIdx + 1);
    result[key] = value;
  }
  return result;
}

/**
 * Extract name and optional @version from a string like "cve" or "top10@2021".
 * Stores results directly into the ParsedSecID.
 */
function extractNameAndVersion(input: string, result: ParsedSecID): void {
  const atIdx = input.indexOf("@");
  if (atIdx !== -1) {
    result.name = input.slice(0, atIdx) || null;
    result.version = input.slice(atIdx + 1) || null;
  } else {
    result.name = input || null;
  }
}
