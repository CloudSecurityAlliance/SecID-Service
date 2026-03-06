/**
 * Seed the in-memory test KV with registry data from the bundled REGISTRY.
 *
 * This mirrors what scripts/upload-registry-kv.ts does for production,
 * but writes directly to the KV binding instead of via wrangler CLI.
 */

import { REGISTRY } from "../../src/registry";
import type { ChildIndexEntry, TypeIndex } from "../../src/types";

const TYPE_DESCRIPTIONS: Record<string, string> = {
  advisory:
    "Publications about vulnerabilities (CVE, GHSA, vendor advisories, incident reports)",
  weakness: "Abstract flaw patterns (CWE, OWASP Top 10)",
  ttp: "Adversary techniques (ATT&CK, ATLAS, CAPEC)",
  control: "Security requirements (NIST CSF, ISO 27001, benchmarks)",
  regulation: "Laws and legal requirements (GDPR, HIPAA)",
  entity: "Organizations, products, services",
  reference:
    "Documents, research, identifier systems (arXiv, DOI, ISBN, RFCs)",
};

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
  let total = 0;

  for (const [type, namespaces] of Object.entries(REGISTRY)) {
    const nsEntries = Object.entries(namespaces).sort(([a], [b]) =>
      a.localeCompare(b)
    );
    typeCounts[type] = nsEntries.length;
    total += nsEntries.length;

    // Write ns:{type}/{namespace} keys
    for (const [ns, data] of nsEntries) {
      await kv.put(`ns:${type}/${ns}`, JSON.stringify(data));
    }

    // Build and write type:{type} key
    const childIndex: ChildIndexEntry[] = [];
    const nsList = nsEntries.map(([ns, data]) => {
      const nsData = data as {
        official_name: string;
        common_name: string | null;
        match_nodes: MatchNodeLike[];
      };
      // Build child_index entries
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
      return {
        namespace: ns,
        official_name: nsData.official_name,
        common_name: nsData.common_name,
        source_count: nsData.match_nodes?.length ?? 0,
      };
    });

    const typeIndex: TypeIndex = {
      type,
      description: TYPE_DESCRIPTIONS[type] ?? type,
      namespaces: nsList,
      child_index: childIndex,
    };
    await kv.put(`type:${type}`, JSON.stringify(typeIndex));
  }

  // Write full:registry
  await kv.put("full:registry", JSON.stringify(REGISTRY));

  // Write meta:registry
  await kv.put(
    "meta:registry",
    JSON.stringify({
      version: new Date().toISOString(),
      total_namespaces: total,
      types: typeCounts,
    })
  );
}
