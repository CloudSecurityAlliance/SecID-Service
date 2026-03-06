import { RegistryContext } from "./kv-registry";
import { extractSecIDType, parseSecID } from "./parser";
import { resolve } from "./resolver";
import {
  SECID_TYPES,
  isResolutionResult,
  type ChildIndexEntry,
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
export async function resolveFromKV(
  kv: KVNamespace,
  input: string
): Promise<ResolveResponse> {
  const ctx = new RegistryContext(kv);

  // 1. Extract type without KV
  const type = extractSecIDType(input);
  if (!type) {
    // No valid type prefix — try bare identifier search across all types.
    // e.g., "CVE-2024-1234" → search all types' child_index for matches.
    const bareResult = await searchBareIdentifier(ctx, input);
    if (bareResult) return bareResult;

    // Nothing matched — let the resolver produce the error message.
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

  // 5. Determine which namespace(s) to fetch
  const namespacesToFetch = determineNamespaces(parsed, typeIndex);

  // 6. Fetch namespace data
  const nsMap = await ctx.getNamespaces(type, namespacesToFetch);

  // 7. Build real (partial) registry and resolve
  const registry = buildPartialRegistry(type, nsMap);
  return resolve(parsed, registry);
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
 * When a user types "CVE-2024-1234" without any SecID structure, this function
 * checks every type's child_index for pattern matches, then resolves across
 * all matching types. This gives the same cross-source results the MCP lookup
 * tool produces.
 */
async function searchBareIdentifier(
  ctx: RegistryContext,
  input: string
): Promise<ResolveResponse | null> {
  const trimmed = input.trim();
  if (!trimmed) return null;

  // Fetch all type indexes in parallel
  const typeIndexes = await Promise.all(
    SECID_TYPES.map(async (type) => ({
      type,
      index: await ctx.getTypeIndex(type),
    }))
  );

  // Find types whose child_index patterns match the input
  const typeMatches: Array<{
    type: SecIDType;
    namespaces: string[];
    index: TypeIndex;
  }> = [];

  for (const { type, index } of typeIndexes) {
    if (!index?.child_index) continue;
    const matchingNs = findMatchingNamespaces(trimmed, index.child_index);
    if (matchingNs.length > 0) {
      typeMatches.push({ type, namespaces: matchingNs, index });
    }
  }

  if (typeMatches.length === 0) return null;

  // Resolve across all matching types in parallel
  const resolveResults = await Promise.all(
    typeMatches.map(async ({ type, namespaces, index }) => {
      const syntheticInput = `secid:${type}/${trimmed}`;
      const minimalRegistry = buildMinimalRegistry(type, index);
      const parsed = parseSecID(syntheticInput, minimalRegistry);
      const nsMap = await ctx.getNamespaces(type, namespaces);
      const registry = buildPartialRegistry(type, nsMap);
      return resolve(parsed, registry);
    })
  );

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
