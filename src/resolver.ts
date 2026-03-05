import type {
  ParsedSecID,
  Registry,
  RegistryNamespace,
  RegistryResult,
  ResolutionResult,
  ResolveResponse,
  MatchNode,
  MatchNodeData,
  VariableDefinition,
  LookupTableEntry,
  ResultEntry,
} from "./types";
import { SECID_TYPES } from "./types";

// ── Main Entry Point ──

export function resolve(
  parsed: ParsedSecID,
  registry: Registry
): ResolveResponse {
  const query = parsed.raw;

  // Invalid or empty input
  if (!parsed.type) {
    if (!parsed.raw || !parsed.raw.trim()) {
      return response(query, "error", [], "Empty query. Provide a SecID string.");
    }
    return response(
      query,
      "not_found",
      [],
      `Invalid type. Valid types: ${SECID_TYPES.join(", ")}`
    );
  }

  const typeRegistry = registry[parsed.type];
  if (!typeRegistry || Object.keys(typeRegistry).length === 0) {
    return response(query, "not_found", [], `No namespaces registered for type "${parsed.type}".`);
  }

  // Type-only query: list namespaces
  if (!parsed.namespace && !parsed.name) {
    return listNamespaces(query, parsed.type, typeRegistry);
  }

  // Has name but no namespace → cross-source search across type
  if (!parsed.namespace && parsed.name) {
    return typeScopedSearch(query, parsed, typeRegistry);
  }

  const ns = typeRegistry[parsed.namespace!];

  // Namespace not in registry
  if (!ns) {
    return response(
      query,
      "not_found",
      [],
      `Namespace "${parsed.namespace}" not found in type "${parsed.type}".`
    );
  }

  // Namespace-only query: list sources
  if (!parsed.name) {
    return listSources(query, parsed, ns);
  }

  // Have namespace + name: try to match against match_nodes
  return resolveWithName(query, parsed, ns, typeRegistry);
}

// ── Level 1: List Namespaces ──

function listNamespaces(
  query: string,
  type: string,
  typeRegistry: Record<string, RegistryNamespace>
): ResolveResponse {
  const results: RegistryResult[] = Object.entries(typeRegistry)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([ns, data]) => ({
      secid: `secid:${type}/${ns}`,
      data: {
        official_name: data.official_name,
        common_name: data.common_name,
        source_count: data.match_nodes.length,
      },
    }));

  return response(query, "found", results);
}

// ── Level 2: List Sources Under a Namespace ──

function listSources(
  query: string,
  parsed: ParsedSecID,
  ns: RegistryNamespace
): ResolveResponse {
  const results: RegistryResult[] = ns.match_nodes.map((node) => {
    const nameSlug = extractNameSlug(node);
    return {
      secid: `secid:${parsed.type}/${parsed.namespace}/${nameSlug}`,
      data: {
        official_name: node.data.official_name ?? node.description,
        common_name: node.data.common_name ?? null,
        description: node.data.description ?? node.description,
        child_count: node.children?.length ?? 0,
      },
    };
  });

  return response(query, "found", results);
}

// ── Level 3+4: Resolve with Name ──

function resolveWithName(
  query: string,
  parsed: ParsedSecID,
  ns: RegistryNamespace,
  typeRegistry: Record<string, RegistryNamespace>
): ResolveResponse {
  // Find matching top-level match_node by name
  const matchedNode = findMatchingNode(ns.match_nodes, parsed.name!);

  if (!matchedNode) {
    // Name didn't match any match_node — try cross-source within this namespace
    const crossResults = namespaceScopedSearch(parsed, ns);
    if (crossResults.length > 0) {
      return response(query, "corrected", crossResults);
    }

    // Try type-wide cross-source
    const typeResults = typeScopedSearch(query, parsed, typeRegistry);
    if (typeResults.results.length > 0) {
      return typeResults;
    }

    return response(
      query,
      "related",
      listSources(query, parsed, ns).results,
      `Name "${parsed.name}" not found in ${parsed.namespace}. Available sources listed.`
    );
  }

  // No subpath → return source-level detail (Level 3)
  if (!parsed.subpath) {
    return describeSource(query, parsed, matchedNode);
  }

  // Has subpath → resolve against children (Level 4)
  return resolveSubpath(query, parsed, matchedNode, ns);
}

// ── Level 3: Describe Source ──

function describeSource(
  query: string,
  parsed: ParsedSecID,
  node: MatchNode
): ResolveResponse {
  const data: Record<string, unknown> = {
    official_name: node.data.official_name ?? node.description,
    common_name: node.data.common_name ?? null,
    description: node.data.description ?? node.description,
    notes: node.data.notes ?? null,
    urls: node.data.urls ?? [],
  };

  if (node.data.version_required) {
    data.version_required = true;
    data.versions_available = node.data.versions_available ?? [];
    data.version_disambiguation = node.data.version_disambiguation ?? null;
  }

  if (node.children && node.children.length > 0) {
    data.patterns = node.children.map((c) => ({
      pattern: c.patterns[0],
      description: c.description,
    }));
  }

  if (node.data.examples && node.data.examples.length > 0) {
    data.examples = node.data.examples;
  }

  const nameSlug = extractNameSlug(node);
  const secid = parsed.version
    ? `secid:${parsed.type}/${parsed.namespace}/${nameSlug}@${parsed.version}`
    : `secid:${parsed.type}/${parsed.namespace}/${nameSlug}`;

  return response(query, "found", [{ secid, data }]);
}

// ── Level 4: Resolve Subpath ──

function resolveSubpath(
  query: string,
  parsed: ParsedSecID,
  node: MatchNode,
  _ns: RegistryNamespace
): ResolveResponse {
  // Handle version_required sources (3-level nesting)
  if (node.data.version_required) {
    return resolveVersioned(query, parsed, node);
  }

  // Standard 2-level: name → children → match subpath
  if (!node.children || node.children.length === 0) {
    return describeSource(query, parsed, node);
  }

  const results = matchChildrenAndResolve(
    node.children,
    parsed.subpath!,
    parsed,
    node
  );

  if (results.length > 0) {
    const filtered = applyContentTypeFilter(results, parsed.qualifiers);
    if (filtered === null) {
      const available = [...new Set(
        results.filter((r): r is ResolutionResult => "url" in r && !!r.content_type)
          .map((r) => r.content_type!)
      )];
      return response(query, "not_found", [],
        `No results with content_type "${parsed.qualifiers!.content_type}". Available: ${available.join(", ") || "none declared"}. Remove ?content_type to see all.`
      );
    }
    return response(query, "found", filtered);
  }

  // Subpath didn't match any child pattern
  return response(
    query,
    "related",
    [describeSource(query, parsed, node).results[0]],
    `Subpath "${parsed.subpath}" did not match any known pattern for this source.`
  );
}

// ── Version-Required Resolution (3-level) ──

function resolveVersioned(
  query: string,
  parsed: ParsedSecID,
  node: MatchNode
): ResolveResponse {
  if (!parsed.version) {
    // No version supplied — return all versions with disambiguation guidance
    const data: Record<string, unknown> = {
      official_name: node.data.official_name ?? node.description,
      version_required: true,
      versions_available: node.data.versions_available ?? [],
      version_disambiguation: node.data.version_disambiguation ?? null,
      unversioned_behavior: node.data.unversioned_behavior ?? null,
    };

    const nameSlug = extractNameSlug(node);
    return response(
      query,
      "related",
      [{ secid: `secid:${parsed.type}/${parsed.namespace}/${nameSlug}`, data }],
      "This source requires a version. Specify @version in your query."
    );
  }

  // Find matching version child
  if (!node.children || node.children.length === 0) {
    return describeSource(query, parsed, node);
  }

  const versionChild = node.children.find((child) =>
    matchesAnyPattern(child.patterns, parsed.version!)
  );

  if (!versionChild) {
    const versions = (node.data.versions_available ?? []).map((v) => v.version);
    return response(
      query,
      "not_found",
      [],
      `Version "${parsed.version}" not found. Available: ${versions.join(", ") || "none listed"}`
    );
  }

  // No subpath — describe version
  if (!parsed.subpath) {
    const nameSlug = extractNameSlug(node);
    const data: Record<string, unknown> = {
      official_name: versionChild.data.official_name ?? versionChild.description,
      urls: versionChild.data.urls ?? [],
      note: versionChild.data.note ?? null,
    };
    if (versionChild.children && versionChild.children.length > 0) {
      data.patterns = versionChild.children.map((c) => ({
        pattern: c.patterns[0],
        description: c.description,
      }));
    }
    return response(query, "found", [{
      secid: `secid:${parsed.type}/${parsed.namespace}/${nameSlug}@${parsed.version}`,
      data,
    }]);
  }

  // Match subpath against version's children (grandchildren of root node)
  if (!versionChild.children || versionChild.children.length === 0) {
    return response(query, "related", [], "This version has no resolvable items.");
  }

  const results = matchChildrenAndResolve(
    versionChild.children,
    parsed.subpath!,
    parsed,
    versionChild,
    node  // root match_node for correct name slug
  );

  if (results.length > 0) {
    const filtered = applyContentTypeFilter(results, parsed.qualifiers);
    if (filtered === null) {
      const available = [...new Set(
        results.filter((r): r is ResolutionResult => "url" in r && !!r.content_type)
          .map((r) => r.content_type!)
      )];
      return response(query, "not_found", [],
        `No results with content_type "${parsed.qualifiers!.content_type}". Available: ${available.join(", ") || "none declared"}. Remove ?content_type to see all.`
      );
    }
    return response(query, "found", filtered);
  }

  return response(
    query,
    "related",
    [],
    `Item "${parsed.subpath}" not found in version ${parsed.version}.`
  );
}

// ── Match Children and Generate URLs ──

function matchChildrenAndResolve(
  children: MatchNode[],
  subpath: string,
  parsed: ParsedSecID,
  parentNode: MatchNode,
  nameNode?: MatchNode
): ResultEntry[] {
  const results: ResultEntry[] = [];
  const slugNode = nameNode ?? parentNode;

  for (const child of children) {
    if (!matchesAnyPattern(child.patterns, subpath)) {
      continue;
    }

    const nameSlug = extractNameSlug(slugNode);
    const secid = parsed.version
      ? `secid:${parsed.type}/${parsed.namespace}/${nameSlug}@${parsed.version}#${subpath}`
      : `secid:${parsed.type}/${parsed.namespace}/${nameSlug}#${subpath}`;

    // Try to build a URL (parentNode has the notes for variable extraction)
    const url = resolveChildUrl(child, subpath, parentNode);

    if (url) {
      const res: ResolutionResult = { secid, weight: child.weight, url };
      if (child.data.content_type) res.content_type = child.data.content_type;
      results.push(res);
    } else if (child.data.lookup_table) {
      // Lookup table: try direct key match
      const entry = child.data.lookup_table[subpath];
      if (entry) {
        const lookupUrl = typeof entry === "string" ? entry : entry.url;
        const res: ResolutionResult = { secid, weight: child.weight, url: lookupUrl };
        if (child.data.content_type) res.content_type = child.data.content_type;
        results.push(res);
      } else {
        // Return the lookup_table as registry data
        results.push({
          secid,
          data: {
            description: child.description,
            available_items: Object.keys(child.data.lookup_table),
          },
        } as RegistryResult);
      }
    } else {
      // No URL pattern — return as registry data
      results.push({
        secid,
        data: {
          description: child.description,
          weight: child.weight,
          note: child.data.note ?? null,
        },
      } as RegistryResult);
    }
  }

  // Sort: ResolutionResults first (by weight desc), then RegistryResults
  results.sort((a, b) => {
    const aIsRes = "url" in a;
    const bIsRes = "url" in b;
    if (aIsRes && bIsRes) {
      return (b as ResolutionResult).weight - (a as ResolutionResult).weight;
    }
    if (aIsRes) return -1;
    if (bIsRes) return 1;
    return 0;
  });

  return results;
}

// ── URL Resolution for a Child Node ──

function resolveChildUrl(
  child: MatchNode,
  subpath: string,
  parentNode: MatchNode
): string | null {
  const urlTemplate = child.data.url;
  if (!urlTemplate) return null;

  // If the template has no placeholders, return as-is
  if (!urlTemplate.includes("{")) return urlTemplate;

  // Extract variables if defined
  const variables: Record<string, string> = {};

  if (child.data.variables) {
    for (const [varName, varDef] of Object.entries(child.data.variables)) {
      const value = extractVariable(varDef, subpath, parentNode.data.notes ?? null);
      if (value !== null) {
        variables[varName] = value;
      }
    }
  }

  // Always provide {id} and common transformations
  variables["id"] = subpath;
  variables["id_lower"] = subpath.toLowerCase();
  variables["id_upper"] = subpath.toUpperCase();

  return buildUrl(urlTemplate, variables);
}

// ── Variable Extraction ──

function extractVariable(
  varDef: VariableDefinition,
  subpath: string,
  parentNotes: string | null
): string | null {
  const re = toRegExp(varDef.extract);
  const match = subpath.match(re);
  if (!match || !match[1]) return null;

  const captured = match[1];

  // Mode 1: Simple extract (no format, no lookup)
  if (!varDef.format && !varDef.lookup) {
    return captured;
  }

  // Mode 2: Extract + format template
  if (varDef.format) {
    return varDef.format.replace(/\{1\}/g, captured);
  }

  // Mode 3: Range table lookup
  if (varDef.lookup === "range_table") {
    return lookupRangeTable(parseInt(captured, 10), parentNotes);
  }

  return captured;
}

// ── Range Table Lookup ──

function lookupRangeTable(
  number: number,
  notes: string | null
): string | null {
  if (!notes) return null;

  // Parse "YYYY: N" pairs from the notes text
  // Format: "2000: 1, 2001: 11, 2002: 96, ..."
  const pairs: Array<{ year: string; start: number }> = [];
  const pairRegex = /(\d{4}):\s*(\d+)/g;
  let m: RegExpExecArray | null;
  while ((m = pairRegex.exec(notes)) !== null) {
    pairs.push({ year: m[1], start: parseInt(m[2], 10) });
  }

  if (pairs.length === 0) return null;

  // Sort by start ascending
  pairs.sort((a, b) => a.start - b.start);

  // Find the highest start <= number
  let result: string | null = null;
  for (const pair of pairs) {
    if (pair.start <= number) {
      result = pair.year;
    } else {
      break;
    }
  }

  return result;
}

// ── URL Template Substitution ──

function buildUrl(
  template: string,
  variables: Record<string, string>
): string {
  let url = template;
  for (const [key, value] of Object.entries(variables)) {
    url = url.replaceAll(`{${key}}`, value);
  }
  return url;
}

// ── Cross-Source Search (Namespace-Scoped) ──

function namespaceScopedSearch(
  parsed: ParsedSecID,
  ns: RegistryNamespace
): ResultEntry[] {
  // The "name" didn't match any match_node name pattern.
  // Treat it as a subpath identifier and try against all children.
  const identifier = parsed.name! + (parsed.subpath ? `${parsed.subpath}` : "");
  const results: ResultEntry[] = [];

  for (const node of ns.match_nodes) {
    if (!node.children) continue;

    for (const child of node.children) {
      if (!matchesAnyPattern(child.patterns, identifier)) continue;

      const nameSlug = extractNameSlug(node);
      const secid = `secid:${parsed.type}/${parsed.namespace}/${nameSlug}#${identifier}`;
      const url = resolveChildUrl(child, identifier, node);

      if (url) {
        const res: ResolutionResult = { secid, weight: child.weight, url };
        if (child.data.content_type) res.content_type = child.data.content_type;
        results.push(res);
      } else {
        results.push({
          secid,
          data: { description: child.description, weight: child.weight },
        } as RegistryResult);
      }
    }
  }

  results.sort((a, b) => {
    const aW = "weight" in a ? (a as ResolutionResult).weight : 0;
    const bW = "weight" in b ? (b as ResolutionResult).weight : 0;
    return bW - aW;
  });

  return results;
}

// ── Cross-Source Search (Type-Scoped) ──

function typeScopedSearch(
  query: string,
  parsed: ParsedSecID,
  typeRegistry: Record<string, RegistryNamespace>
): ResolveResponse {
  const identifier = parsed.name ?? "";
  if (!identifier) {
    return response(query, "not_found", [], "No identifier to search for.");
  }

  const results: ResultEntry[] = [];

  for (const [nsKey, ns] of Object.entries(typeRegistry)) {
    for (const node of ns.match_nodes) {
      if (!node.children) continue;

      for (const child of node.children) {
        if (!matchesAnyPattern(child.patterns, identifier)) continue;

        const nameSlug = extractNameSlug(node);
        const secid = `secid:${parsed.type}/${nsKey}/${nameSlug}#${identifier}`;
        const url = resolveChildUrl(child, identifier, node);

        if (url) {
          const res: ResolutionResult = { secid, weight: child.weight, url };
          if (child.data.content_type) res.content_type = child.data.content_type;
          results.push(res);
        } else {
          results.push({
            secid,
            data: { description: child.description, weight: child.weight },
          } as RegistryResult);
        }
      }
    }
  }

  if (results.length === 0) {
    return response(query, "not_found", [], `No results found for "${identifier}" in type "${parsed.type}".`);
  }

  results.sort((a, b) => {
    const aW = "weight" in a ? (a as ResolutionResult).weight : 0;
    const bW = "weight" in b ? (b as ResolutionResult).weight : 0;
    if (bW !== aW) return bW - aW;
    return (a as { secid: string }).secid.localeCompare((b as { secid: string }).secid);
  });

  return response(query, "found", results);
}

// ── Helpers ──

function findMatchingNode(
  nodes: MatchNode[],
  name: string
): MatchNode | null {
  for (const node of nodes) {
    if (matchesAnyPattern(node.patterns, name)) {
      return node;
    }
  }
  return null;
}

function matchesAnyPattern(patterns: string[], input: string): boolean {
  for (const pat of patterns) {
    try {
      if (toRegExp(pat).test(input)) return true;
    } catch {
      // Invalid regex — skip
    }
  }
  return false;
}

/** Convert a pattern string to a RegExp, handling (?i) inline flag → JS 'i' flag. */
function toRegExp(pat: string): RegExp {
  if (pat.startsWith("(?i)")) {
    return new RegExp(pat.slice(4), "i");
  }
  return new RegExp(pat);
}

function extractNameSlug(node: MatchNode): string {
  // Extract a human-readable name from the first pattern
  // Patterns like "(?i)^cve$" → "cve"
  const pat = node.patterns[0] ?? "";
  const cleaned = pat
    .replace(/^\(\?i\)/i, "")
    .replace(/^\^/, "")
    .replace(/\$$/, "");
  // If it's a simple literal (no regex meta), use it
  if (/^[\w-]+$/.test(cleaned)) {
    return cleaned.toLowerCase();
  }
  // Fallback: use description
  return node.description.toLowerCase().replace(/\s+/g, "-");
}

function applyContentTypeFilter(
  results: ResultEntry[],
  qualifiers: Record<string, string> | null
): ResultEntry[] | null {
  if (!qualifiers?.content_type) return results;
  const target = qualifiers.content_type;
  const filtered = results.filter((r) => {
    if (!("url" in r)) return true; // Keep RegistryResults (metadata)
    return (r as ResolutionResult).content_type === target;
  });
  // If all ResolutionResults were filtered out, signal "not found"
  const hasResolution = filtered.some((r) => "url" in r);
  if (!hasResolution && results.some((r) => "url" in r)) return null;
  return filtered;
}

function response(
  query: string,
  status: ResolveResponse["status"],
  results: ResultEntry[],
  message?: string
): ResolveResponse {
  const r: ResolveResponse = { secid_query: query, status, results };
  if (message) r.message = message;
  return r;
}
