import { RegistryContext } from "./kv-registry";
import { extractSecIDType, parseSecID } from "./parser";
import { resolve, isOpenPattern, toRegExp, MAX_REGEX_INPUT_CHARS } from "./resolver";
import { recordDemandMiss, type DemandChannel } from "./demand";
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
 * Optional hook for capturing namespace-level misses. When `demand` is
 * provided, a `not_found` whose namespace isn't in the type index (a recognized
 * type + an unregistered namespace) is written to Analytics Engine as a demand
 * data point (src/demand.ts). `feedbackKv` is the submit_feedback store; it is
 * carried here because the MCP server receives both through one object.
 */
export interface MissCapture {
  demand?: AnalyticsEngineDataset;
  channel?: DemandChannel;
  feedbackKv?: KVNamespace;
}

export async function resolveFromKV(
  kv: KVNamespace,
  input: string,
  capture?: MissCapture
): Promise<ResolveResponse> {
  const ctx = new RegistryContext(kv);

  // 0. Root query: "secid" or "secid:" → list every type
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
    if (!hasSecidPrefix && input.trim()) {
      const bareResult = await searchBareIdentifier(ctx, input);
      if (bareResult) return bareResult;
      return bareSearchNotFound(input);
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
  if (!parsed.namespace && (!parsed.name || parsed.name === "*")) {
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
  let namespacesToFetch: string[];
  if (!parsed.namespace && parsed.name) {
    // Cross-source search. Resolve against candidate namespaces from the
    // indexes only — never by fetching every namespace of the type.
    namespacesToFetch = await crossSourceCandidates(ctx, type, parsed.name, typeIndex);
    if (namespacesToFetch.length === 0) {
      return {
        secid_query: input,
        status: "not_found",
        results: [],
        message: `No results found for "${parsed.name}" in type "${type}". If this source should be covered, request it at https://github.com/CloudSecurityAlliance/SecID/issues`,
      };
    }
  } else {
    namespacesToFetch = determineNamespaces(parsed, typeIndex);
  }

  // 6. Fetch namespace data
  const nsMap = await ctx.getNamespaces(type, namespacesToFetch);

  // 7. Build real (partial) registry and resolve
  const registry = buildPartialRegistry(type, nsMap);
  const result = resolve(parsed, registry);

  // Detect a namespace-level miss authoritatively from the TypeIndex (the full
  // namespace list), not from the resolver's message. In the KV flow only the
  // requested namespace is fetched, so on a miss the partial registry is empty
  // and resolve() reports "no namespaces registered for type" rather than
  // "namespace not found" — either way, if the parsed namespace isn't in the
  // index, it's the actionable "we should add this" signal.
  const isNamespaceMiss =
    result.status === "not_found" &&
    !!parsed.namespace &&
    !typeIndex.namespaces.some((n) => n.namespace === parsed.namespace);

  if (isNamespaceMiss) {
    result.message = `Namespace "${parsed.namespace}" not found in type "${type}". MCP clients can request it with the submit_feedback tool.`;

    // Demand is keyed case-insensitively, so a case variant of a registered
    // namespace is not a gap and is not recorded.
    const lower = parsed.namespace!.toLowerCase();
    const registeredCaseVariant = typeIndex.namespaces.some(
      (n) => n.namespace.toLowerCase() === lower
    );
    if (capture?.demand && !registeredCaseVariant) {
      recordDemandMiss(capture.demand, {
        type,
        namespace: parsed.namespace!,
        channel: capture.channel ?? "rest",
        status: result.status,
      });
    }
  }

  return result;
}

/**
 * A bare term (no "secid:" prefix, no recognised type) that matched nothing.
 *
 * The input was a search, not a malformed SecID, so "Invalid type" is the
 * wrong answer: it blames the user for a grammar they never attempted. Say
 * what was searched and how to go further. If the term has a slash, the first
 * segment may have been meant as a type, so list the valid ones too.
 */
function bareSearchNotFound(input: string): ResolveResponse {
  const term = input.trim();
  let message =
    `No matches for "${term}". A bare term is searched across every type as an identifier ` +
    `(e.g. CVE-2021-44228), a source name (e.g. cwe) and a namespace name (e.g. fedramp). ` +
    `Try a scoped query such as secid:advisory/${term}, or "secid:" to list the types.`;
  const slash = term.indexOf("/");
  if (slash > 0) {
    message += ` If "${term.slice(0, slash)}" was meant as a type, valid types are: ${SECID_TYPES.join(", ")}.`;
  }
  return { secid_query: input, status: "not_found", results: [], message };
}

/**
 * Resolve a query exactly as given, then — only if that did not resolve —
 * once more percent-decoded.
 *
 * SPEC §8: resolvers try the input as-is first, then percent-decoded. The
 * as-is form is authoritative because SecIDs are written unencoded (A&A-01,
 * not A%26A-01) and an identifier may contain a literal '%'. Decoding first,
 * as the REST handler used to (on top of the framework's own query-string
 * decoding), turned "%41" into "A" and rejected any literal '%' as malformed.
 * The fallback still rescues clients that encode the SecID twice or send
 * '#' as %23 through a transport that does not decode it (MCP arguments).
 *
 * `secid_query` always echoes what the client sent.
 */
export async function resolveQuery(
  kv: KVNamespace,
  input: string,
  capture?: MissCapture
): Promise<ResolveResponse> {
  const asIs = await resolveFromKV(kv, input, capture);
  if (asIs.status === "found" || asIs.status === "corrected") return asIs;
  if (!/%[0-9A-Fa-f]{2}/.test(input)) return asIs;

  let decoded: string;
  try {
    decoded = decodeURIComponent(input);
  } catch {
    return asIs; // Not valid percent-encoding, so a literal '%' — as-is stands.
  }
  if (decoded === input) return asIs;

  const alt = await resolveFromKV(kv, decoded, capture);
  return STATUS_RANK[alt.status] > STATUS_RANK[asIs.status]
    ? { ...alt, secid_query: input }
    : asIs;
}

const STATUS_RANK: Record<ResolveResponse["status"], number> = {
  error: 0,
  not_found: 1,
  related: 2,
  corrected: 3,
  found: 4,
};

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

  // Cross-source search is handled by crossSourceCandidates; type-only
  // listings are answered from the TypeIndex before we get here.
  return [];
}

/**
 * Namespaces that could answer a cross-source search (`secid:<type>/<term>`).
 *
 * The resolver's typeScopedSearch reports three kinds of hit: a child pattern
 * (an item identifier), a source-level pattern (the source's own name, "cwe"),
 * and a namespace identity (the org's name, "ismap"). Each has an index:
 *
 *   - child patterns   → this type's TypeIndex.child_index (already loaded)
 *   - source patterns  → the global index's level:"source" entries
 *   - identities       → the global index's name_index
 *
 * Child matches on a discriminating (non-open) pattern keep their existing
 * precedence: when any exist, they alone decide the candidate set, exactly as
 * before. Otherwise the two global indexes supply candidates in a single KV
 * read, alongside any open-pattern child matches.
 *
 * This replaces a fallback that fetched every namespace of the type when no
 * child pattern matched — about a thousand KV reads for `entity` and seconds of
 * latency, reachable by any unmatched term. It returns the same results: a
 * namespace outside these candidates cannot produce a typeScopedSearch hit,
 * because each kind of hit is exactly what one of the indexes records. Open
 * source-level patterns are skipped, mirroring nodeMatches() for an unscoped
 * search (no registry source node pairs an open pattern with known_values).
 *
 * An empty result means not_found without touching namespace data. If the
 * global index is missing (an older deploy), that is also the answer: failing
 * closed to not_found is better than reopening the full scan.
 */
async function crossSourceCandidates(
  ctx: RegistryContext,
  type: SecIDType,
  name: string,
  typeIndex: TypeIndex
): Promise<string[]> {
  const tight = typeIndex.child_index.filter((e) => !isOpenPattern(e.patterns));
  const open = typeIndex.child_index.filter((e) => isOpenPattern(e.patterns));
  const tightMatches = findMatchingNamespaces(name, tight);
  if (tightMatches.length > 0) return tightMatches;

  // An open child pattern matches almost any term, so it is a candidate (its
  // known_values may still contain the term) but it is no evidence that the
  // term is an item identifier. Letting it pre-empt the source and identity
  // candidates is what made `secid:reference/arxiv` miss arxiv.org.
  const matched = new Set<string>(findMatchingNamespaces(name, open));

  const globalIndex = await ctx.getGlobalIndex();
  if (!globalIndex) return [...matched];

  if (name.length <= MAX_REGEX_INPUT_CHARS) {
    for (const entry of globalIndex.child_index ?? []) {
      if (entry.type !== type || entry.level !== "source") continue;
      if (entry.open ?? isOpenPattern(entry.patterns)) continue;
      if (matched.has(entry.namespace)) continue;
      if (entry.patterns.some((pat) => testPattern(pat, name))) matched.add(entry.namespace);
    }
  }

  const needle = name.trim().toLowerCase();
  if (needle) {
    for (const entry of globalIndex.name_index ?? []) {
      if (entry.type === type && entry.aliases.includes(needle)) matched.add(entry.namespace);
    }
  }

  return [...matched];
}

function testPattern(pat: string, input: string): boolean {
  try {
    const re = pat.startsWith("(?i)") ? new RegExp(pat.slice(4), "i") : new RegExp(pat);
    return re.test(input);
  } catch {
    return false; // Invalid regex — skip
  }
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
  if (identifier.length > MAX_REGEX_INPUT_CHARS) return []; // ReDoS bound
  const matched = new Set<string>();
  for (const entry of childIndex) {
    for (const pat of entry.patterns) {
      try {
        if (toRegExp(pat).test(identifier)) {
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
 * then resolves across all matches. One KV read instead of one per type.
 */
async function searchBareIdentifier(
  ctx: RegistryContext,
  input: string
): Promise<ResolveResponse | null> {
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > MAX_REGEX_INPUT_CHARS) return null; // ReDoS bound

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
    // An open pattern must not answer a bare term. This is still an unscoped
    // search even though a source-level hit is resolved as a fully-qualified
    // query below — without this, github.com/users answered every free-text
    // query because its username pattern matches any token.
    // `open` is absent on older index deploys, so fall back to detection.
    if (entry.open ?? isOpenPattern(entry.patterns)) continue;
    for (const pat of entry.patterns) {
      try {
        if (toRegExp(pat).test(trimmed)) {
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

  // Namespace identity matches — the user typed an org or programme name that
  // no source slug would surface (e.g. "ismap", whose only source is called
  // "control-criteria"). Selecting the namespace here is enough; the resolver's
  // own identity check turns it into a result.
  const needle = trimmed.toLowerCase();
  for (const entry of globalIndex.name_index ?? []) {
    if (!entry.aliases.includes(needle)) continue;
    const type = entry.type as SecIDType;
    if (!childMatchesByType.has(type)) childMatchesByType.set(type, new Set());
    childMatchesByType.get(type)!.add(entry.namespace);
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
