import { RegistryContext } from "./kv-registry";
import { extractSecIDType, parseSecID } from "./parser";
import { resolve } from "./resolver";
import { recordMiss } from "./feedback";
import {
  isResolutionResult,
  SECID_TYPES,
  type ChildIndexEntry,
  type GlobalChildIndexEntry,
  type ParsedSecID,
  type Registry,
  type RegistryNamespace,
  type ResolveResponse,
  type ResultEntry,
  type SecIDType,
  type TypeIndex,
} from "./types";

/**
 * Resolve a SecID string using KV-backed registry data.
 *
 * Flow:
 * 1. Extract type from input (no KV needed)
 * 2. Fetch TypeIndex for namespace list + child_index
 * 3. Build minimal Registry for parser (namespace keys as placeholders)
 * 4. Parse SecID against that minimal registry
 * 5. Fetch the namespace(s) needed for resolution
 * 6. Build a real (but partial) Registry and resolve
 */
/**
 * Optional hook for capturing namespace-level misses. When provided, a
 * `not_found` carrying a `submission_url` (i.e. a recognized type + a
 * namespace that isn't registered) is recorded to the feedback KV. Passing
 * `waitUntil` keeps the KV write off the response path.
 */
export interface MissCapture {
  feedbackKv?: KVNamespace;
  waitUntil?: (p: Promise<unknown>) => void;
}

export async function resolveFromKV(
  kv: KVNamespace,
  input: string,
  capture?: MissCapture
): Promise<ResolveResponse> {
  const ctx = new RegistryContext(kv);

  // 0. Root query: "secid" or "secid:" → list all 8 types
  const trimmed = input.trim();
  if (/^secid:?$/i.test(trimmed)) {
    const types: Array<{ type: string; description: string; namespace_count: number }> = [];
    for (const t of SECID_TYPES) {
      const ti = await ctx.getTypeIndex(t);
      if (ti) {
        types.push({
          type: t,
          description: ti.description,
          namespace_count: ti.namespace_count,
        });
      }
    }
    return {
      secid_query: input,
      status: "found" as const,
      results: types.map((t) => ({
        secid: `secid:${t.type}`,
        data: {
          description: t.description,
          namespace_count: t.namespace_count,
        },
      })),
    };
  }

  // 1. Extract type without KV
  const type = extractSecIDType(input);
  if (!type) {
    // No valid type. Two sub-cases:
    //   (a) Input has no "secid:" prefix → treat as bare identifier; search
    //       all types' indices for matches (e.g., "CVE-2024-1234", "cwe").
    //   (b) Input HAS "secid:" prefix but the type is unknown → user explicitly
    //       typed an invalid SecID; don't fish for matches. Fall through to
    //       the resolver's invalid-type error path.
    const hasSecidPrefix = /^secid:/i.test(input.trimStart());
    if (!hasSecidPrefix) {
      const bareResult = await searchBareIdentifier(ctx, input);
      if (bareResult) return bareResult;
    }

    // Nothing matched (or invalid explicit SecID) — let the resolver produce the error message.
    const parsed = parseSecID(input, {});
    return resolve(parsed, {});
  }

  // 2. Fetch TypeIndex
  const typeIndex = await ctx.getTypeIndex(type);
  if (!typeIndex) {
    // Type exists in grammar but no data in KV — return not_found
    const parsed = parseSecID(input, {});
    return resolve(parsed, {});
  }

  // 3. Build minimal registry for parser (just namespace keys)
  const minimalRegistry = buildMinimalRegistry(type, typeIndex);

  // 4. Parse
  const parsed = parseSecID(input, minimalRegistry);

  // Type-only query — return type metadata from TypeIndex directly
  // (avoids fetching all 502+ disclosure namespaces just to list them)
  if (!parsed.namespace && !parsed.name) {
    return {
      secid_query: input,
      status: "found" as const,
      results: [{
        secid: `secid:${type}`,
        data: {
          description: typeIndex.description,
          purpose: typeIndex.purpose ?? null,
          format: typeIndex.format ?? null,
          examples: typeIndex.examples ?? [],
          notes: typeIndex.notes ?? null,
          namespace_count: typeIndex.namespace_count,
          namespaces: typeIndex.namespaces,
        },
      }],
    };
  }

  // 5. Determine which namespace(s) to fetch
  const namespacesToFetch = determineNamespaces(parsed, typeIndex);

  // 6. Fetch namespace data
  const nsMap = await ctx.getNamespaces(type, namespacesToFetch);

  // 7. Build real (partial) registry and resolve
  const registry = buildPartialRegistry(type, nsMap);
  const result = resolve(parsed, registry);

  // Capture namespace-level misses. The resolver only sets submission_url when
  // a recognized type names a namespace that isn't registered — exactly the
  // actionable "we should add this" signal.
  if (
    capture?.feedbackKv &&
    result.status === "not_found" &&
    result.submission_url &&
    parsed.type &&
    parsed.namespace
  ) {
    const write = recordMiss(capture.feedbackKv, parsed.type, parsed.namespace, input);
    if (capture.waitUntil) capture.waitUntil(write);
    else await write;
  }

  return result;
}

/**
 * Build a minimal registry with empty namespace placeholders.
 * The parser only checks `candidate in typeRegistry` — it doesn't
 * read namespace data. So empty objects suffice.
 */
function buildMinimalRegistry(
  type: string,
  typeIndex: TypeIndex
): Registry {
  const typeRegistry: Record<string, RegistryNamespace> = {};
  for (const entry of typeIndex.namespaces) {
    // Minimal placeholder — parser only checks key existence
    typeRegistry[entry.namespace] = {} as RegistryNamespace;
  }
  return { [type]: typeRegistry };
}

/**
 * Determine which namespaces need to be fetched for resolution.
 *
 * - If parsed has a namespace → fetch that namespace
 * - If cross-source search (no namespace, has name) → use child_index to find matches
 * - If type-only listing → no namespace fetch needed (TypeIndex has the listing data,
 *   but the resolver wants real namespace objects — fetch all)
 */
function determineNamespaces(
  parsed: ReturnType<typeof parseSecID>,
  typeIndex: TypeIndex
): string[] {
  // Has a matched namespace — fetch it
  if (parsed.namespace) {
    const namespaces = [parsed.namespace];

    // Also find cross-source matches for the fallback path in resolveWithName.
    // The resolver calls typeScopedSearch when name doesn't match any match_node,
    // so we need those namespaces too. But we only know if name matches after
    // fetching the namespace data. To keep it simple: if there's a subpath or name
    // that looks like an identifier (not a name slug), pre-fetch cross-source matches.
    if (parsed.name && parsed.subpath) {
      const crossSource = findMatchingNamespaces(
        parsed.subpath,
        typeIndex.child_index
      );
      for (const ns of crossSource) {
        if (!namespaces.includes(ns)) namespaces.push(ns);
      }
    }

    return namespaces;
  }

  // Cross-source search: no namespace, has name (identifier)
  if (parsed.name) {
    const matches = findMatchingNamespaces(parsed.name, typeIndex.child_index);
    return matches.length > 0
      ? matches
      : typeIndex.namespaces.map((n) => n.namespace);
  }

  // Type-only query — resolver needs all namespaces for listing
  return typeIndex.namespaces.map((n) => n.namespace);
}

/**
 * Pattern-match an identifier against the child_index to find which
 * namespaces have matching children. Uses the pre-computed patterns
 * from the TypeIndex.
 */
function findMatchingNamespaces(
  identifier: string,
  childIndex: ChildIndexEntry[]
): string[] {
  const matched = new Set<string>();
  for (const entry of childIndex) {
    for (const pat of entry.patterns) {
      try {
        const re = pat.startsWith("(?i)")
          ? new RegExp(pat.slice(4), "i")
          : new RegExp(pat);
        if (re.test(identifier)) {
          matched.add(entry.namespace);
          break;
        }
      } catch {
        // Invalid regex — skip
      }
    }
  }
  return [...matched];
}

/**
 * Build a partial Registry object from fetched namespace data.
 */
function buildPartialRegistry(
  type: string,
  nsMap: Map<string, RegistryNamespace>
): Registry {
  const typeRegistry: Record<string, RegistryNamespace> = {};
  for (const [ns, data] of nsMap) {
    typeRegistry[ns] = data;
  }
  return { [type]: typeRegistry };
}

/**
 * Search for a bare identifier (no secid: prefix, no type) across all types.
 *
 * Fetches the "secid:*" KV key — a single combined child_index across all types.
 * Pattern-matches the input to find which type(s) and namespace(s) contain it,
 * then resolves across all matches. One KV read instead of seven.
 */
async function searchBareIdentifier(
  ctx: RegistryContext,
  input: string
): Promise<ResolveResponse | null> {
  const trimmed = input.trim();
  if (!trimmed) return null;

  // Single KV read: combined index across all types
  const globalIndex = await ctx.getGlobalIndex();
  if (!globalIndex?.child_index) return null;

  // Pattern-match against the global index. Source-level and child-level
  // matches go through different resolution paths — a "cwe" match is a
  // source identity (resolve weakness/mitre.org/cwe), whereas a "CVE-2021-44228"
  // match is a cross-source item lookup.
  const sourceMatches: Array<{ type: SecIDType; namespace: string; nameSlug: string }> = [];
  const childMatchesByType = new Map<SecIDType, Set<string>>();
  for (const entry of globalIndex.child_index) {
    for (const pat of entry.patterns) {
      try {
        const re = pat.startsWith("(?i)")
          ? new RegExp(pat.slice(4), "i")
          : new RegExp(pat);
        if (re.test(trimmed)) {
          // entry.level may be absent on older deploys — treat as "child" for compat
          if (entry.level === "source") {
            sourceMatches.push({
              type: entry.type,
              namespace: entry.namespace,
              nameSlug: entry.name_slug,
            });
          } else {
            if (!childMatchesByType.has(entry.type)) {
              childMatchesByType.set(entry.type, new Set());
            }
            childMatchesByType.get(entry.type)!.add(entry.namespace);
          }
          break;
        }
      } catch {
        // Invalid regex — skip
      }
    }
  }

  if (sourceMatches.length === 0 && childMatchesByType.size === 0) return null;

  // Resolve source-level matches: each becomes a fully-qualified query
  // (namespace + name set) so the resolver returns the source itself.
  const sourceResolvePromises = sourceMatches.map(async ({ type, namespace, nameSlug }) => {
    const parsed: ParsedSecID = {
      raw: input,
      prefix: false,
      type,
      namespace,
      name: nameSlug,
      version: null,
      subpath: null,
      itemVersion: null,
      qualifiers: null,
    };
    const nsMap = await ctx.getNamespaces(type, [namespace]);
    const registry = buildPartialRegistry(type, nsMap);
    return resolve(parsed, registry);
  });

  // Resolve child-level matches: existing type-scoped cross-source search.
  const childResolvePromises = [...childMatchesByType.entries()].map(async ([type, namespaces]) => {
    const parsed: ParsedSecID = {
      raw: input,
      prefix: false,
      type,
      namespace: null,
      name: trimmed,
      version: null,
      subpath: null,
      itemVersion: null,
      qualifiers: null,
    };
    const nsMap = await ctx.getNamespaces(type, [...namespaces]);
    const registry = buildPartialRegistry(type, nsMap);
    return resolve(parsed, registry);
  });

  const resolveResults = await Promise.all([
    ...sourceResolvePromises,
    ...childResolvePromises,
  ]);

  // Aggregate results from all types
  const allResults: ResultEntry[] = [];
  for (const result of resolveResults) {
    if (result.results.length > 0) {
      allResults.push(...result.results);
    }
  }

  if (allResults.length === 0) return null;

  // Sort: ResolutionResults first (by weight desc), then RegistryResults
  allResults.sort((a, b) => {
    const aIsRes = isResolutionResult(a);
    const bIsRes = isResolutionResult(b);
    if (aIsRes && bIsRes) return b.weight - a.weight;
    if (aIsRes) return -1;
    if (bIsRes) return 1;
    return 0;
  });

  return {
    secid_query: input,
    status: "found",
    results: allResults,
  };
}
