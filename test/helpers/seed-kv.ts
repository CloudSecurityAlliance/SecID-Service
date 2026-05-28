/**
 * Seed the in-memory test KV with registry data from the bundled REGISTRY.
 *
 * This mirrors what scripts/upload-registry-kv.ts does for production,
 * but writes directly to the KV binding instead of via wrangler CLI.
 */

import { REGISTRY } from "../../src/registry";
import type { ChildIndexEntry, TypeIndex } from "../../src/types";
import { TYPE_SHORT_DESCRIPTIONS } from "../../src/type-registry";

interface MatchNodeLike {
  patterns: string[];
  description: string;
  weight: number;
  data: Record<string, unknown>;
  children?: MatchNodeLike[];
}

function extractNameSlug(node: MatchNodeLike): string {
  const pat = node.patterns[0] ?? "";
  const cleaned = pat
    .replace(/^\(\?i\)/i, "")
    .replace(/^\^/, "")
    .replace(/\$$/, "");
  if (/^[\w-]+$/.test(cleaned)) {
    return cleaned.toLowerCase();
  }
  return node.description.toLowerCase().replace(/\s+/g, "-");
}

export async function seedRegistryKV(kv: KVNamespace): Promise<void> {
  const typeCounts: Record<string, number> = {};
  // Combined index across all types — must mirror the production upload script
  // (scripts/upload-registry-kv.ts) so tests exercise the same bare-name and
  // cross-source search paths the live deploy hits.
  const globalChildIndex: Array<ChildIndexEntry & { type: string; level: "source" | "child" }> = [];
  let total = 0;

  for (const [type, namespaces] of Object.entries(REGISTRY)) {
    const nsEntries = Object.entries(namespaces).sort(([a], [b]) =>
      a.localeCompare(b)
    );
    typeCounts[type] = nsEntries.length;
    total += nsEntries.length;

    // Write secid:{type}/{namespace} keys
    for (const [ns, data] of nsEntries) {
      await kv.put(`secid:${type}/${ns}`, JSON.stringify(data));
    }

    // Build and write secid:{type} key
    const childIndex: ChildIndexEntry[] = [];
    const nsList = nsEntries.map(([ns, data]) => {
      const nsData = data as {
        official_name: string;
        common_name: string | null;
        match_nodes: MatchNodeLike[];
      };
      // Build child_index entries (per-type — child level only; matches the
      // production TypeIndex shape).
      for (const node of nsData.match_nodes ?? []) {
        const nameSlug = extractNameSlug(node);
        for (const child of node.children ?? []) {
          childIndex.push({
            namespace: ns,
            name_slug: nameSlug,
            patterns: child.patterns,
            description: child.description,
            weight: child.weight,
            has_url: !!child.data?.url,
          });
        }
      }
      // Build global index entries (both source-level and child-level —
      // matches the production secid:* key shape).
      for (const node of nsData.match_nodes ?? []) {
        const nameSlug = extractNameSlug(node);
        globalChildIndex.push({
          type,
          namespace: ns,
          name_slug: nameSlug,
          level: "source",
          patterns: node.patterns,
          description: node.description,
          weight: node.weight ?? 100,
          has_url: !!(node.data?.url),
        });
        for (const child of node.children ?? []) {
          globalChildIndex.push({
            type,
            namespace: ns,
            name_slug: nameSlug,
            level: "child",
            patterns: child.patterns,
            description: child.description,
            weight: child.weight,
            has_url: !!child.data?.url,
          });
        }
      }
      // Union of subtype values across all source-level match_nodes — mirrors
      // the production upload script so filter tests can exercise the same
      // shape the live deploy returns.
      const subtypes = new Set<string>();
      for (const node of nsData.match_nodes ?? []) {
        const raw = (node.data as Record<string, unknown> | undefined)?.subtype;
        if (Array.isArray(raw)) {
          for (const v of raw) if (typeof v === "string") subtypes.add(v);
        } else if (typeof raw === "string") {
          subtypes.add(raw);
        }
      }
      return {
        namespace: ns,
        official_name: nsData.official_name,
        common_name: nsData.common_name,
        source_count: nsData.match_nodes?.length ?? 0,
        subtypes: [...subtypes].sort(),
      };
    });

    const typeIndex: TypeIndex = {
      type,
      description: TYPE_SHORT_DESCRIPTIONS[type] ?? type,
      namespace_count: nsList.length,
      namespaces: nsList,
      child_index: childIndex,
    };
    await kv.put(`secid:${type}`, JSON.stringify(typeIndex));
  }

  // Write secid:* (global index for bare-name lookup)
  await kv.put("secid:*", JSON.stringify({ child_index: globalChildIndex }));

  // Write secid:registry
  await kv.put("secid:registry", JSON.stringify(REGISTRY));

  // Write secid:meta
  await kv.put(
    "secid:meta",
    JSON.stringify({
      version: new Date().toISOString(),
      total_namespaces: total,
      types: typeCounts,
    })
  );
}
