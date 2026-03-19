/**
 * Upload registry data to Cloudflare KV.
 *
 * Reads all JSON registry files and writes:
 *   - ns:{type}/{namespace}  — raw namespace JSON (×121)
 *   - type:{type}            — TypeIndex with child_index (×7)
 *   - secid                  — GlobalIndex: combined child_index across all types (×1)
 *   - full:registry          — complete compiled Registry (×1)
 *   - meta:registry          — version/counts metadata (×1)
 *
 * Usage: npx tsx scripts/upload-registry-kv.ts [--preview] [path-to-secid-repo]
 */

import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { homedir } from "os";
import { execFileSync } from "child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Parse arguments
const args = process.argv.slice(2);
const preview = args.includes("--preview");
const nonFlags = args.filter((a) => !a.startsWith("--"));
const secidRepo =
  nonFlags[0] || join(homedir(), "GitHub", "CloudSecurityAlliance", "SecID");
const registryDir = join(secidRepo, "registry");

const PRODUCTION_NS_ID = "cfbc271787614516a39fa43d9ca4f95a";
const PREVIEW_NS_ID = "bda410b73cc34b468c84bf2dc9fba45f";
const MAX_KV_VALUE_BYTES = 25 * 1024 * 1024; // 25 MiB (Cloudflare KV max value size)

interface RegistryFile {
  namespace: string;
  type: string;
  official_name: string;
  common_name: string | null;
  match_nodes: MatchNodeRaw[];
  [key: string]: unknown;
}

interface MatchNodeRaw {
  patterns: string[];
  description: string;
  weight: number;
  data: Record<string, unknown>;
  children?: MatchNodeRaw[];
}

interface ChildIndexEntry {
  namespace: string;
  name_slug: string;
  patterns: string[];
  description: string;
  weight: number;
  has_url: boolean;
}

interface TypeIndex {
  type: string;
  description: string;
  namespaces: Array<{
    namespace: string;
    official_name: string;
    common_name: string | null;
    source_count: number;
  }>;
  child_index: ChildIndexEntry[];
}

interface BulkEntry {
  key: string;
  value: string;
}

// Type descriptions for the TypeIndex
const TYPE_DESCRIPTIONS: Record<string, string> = {
  advisory:
    "Publications about vulnerabilities (CVE, GHSA, vendor advisories, incident reports)",
  weakness: "Abstract flaw patterns (CWE, OWASP Top 10)",
  ttp: "Adversary techniques (ATT&CK, ATLAS, CAPEC)",
  control: "Security requirements (NIST CSF, ISO 27001, benchmarks)",
  disclosure:
    "Vulnerability disclosure programs, policies, reporting channels",
  regulation: "Laws and legal requirements (GDPR, HIPAA)",
  entity: "Organizations, products, services",
  reference:
    "Documents, research, identifier systems (arXiv, DOI, ISBN, RFCs)",
};

// ── File Discovery ──

function findJsonFiles(dir: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith("_")) continue;
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      results.push(...findJsonFiles(fullPath));
    } else if (entry.endsWith(".json")) {
      results.push(fullPath);
    }
  }
  return results;
}

// ── Name Slug Extraction ──

function extractNameSlug(node: MatchNodeRaw): string {
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

// ── Build KV Entries ──

function buildEntries(): BulkEntry[] {
  const files = findJsonFiles(registryDir);
  const registry: Record<string, Record<string, RegistryFile>> = {};
  const entries: BulkEntry[] = [];
  let count = 0;

  // Parse all JSON files
  for (const filePath of files) {
    const raw = readFileSync(filePath, "utf-8");
    let data: RegistryFile;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      console.error(`FAIL: ${filePath} — ${e}`);
      continue;
    }
    const { type, namespace } = data;
    if (!type || !namespace) {
      console.error(`SKIP: ${filePath} — missing type or namespace`);
      continue;
    }
    if (!registry[type]) registry[type] = {};
    registry[type][namespace] = data;
    count++;

    // ns:{type}/{namespace} — raw namespace JSON
    entries.push({
      key: `ns:${type}/${namespace}`,
      value: raw,
    });
  }

  // type:{type} — TypeIndex with child_index
  const types = Object.keys(registry).sort();
  const typeCounts: Record<string, number> = {};

  for (const type of types) {
    const namespaces = Object.entries(registry[type])
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([ns, data]) => ({
        namespace: ns,
        official_name: data.official_name,
        common_name: data.common_name,
        source_count: data.match_nodes?.length ?? 0,
      }));

    typeCounts[type] = namespaces.length;

    // Build child_index
    const childIndex: ChildIndexEntry[] = [];
    for (const [ns, data] of Object.entries(registry[type])) {
      if (!data.match_nodes) continue;
      for (const node of data.match_nodes) {
        const nameSlug = extractNameSlug(node);
        if (!node.children) continue;
        for (const child of node.children) {
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
    }

    const typeIndex: TypeIndex = {
      type,
      description: TYPE_DESCRIPTIONS[type] ?? type,
      namespaces,
      child_index: childIndex,
    };

    entries.push({
      key: `type:${type}`,
      value: JSON.stringify(typeIndex),
    });
  }

  // secid — GlobalIndex: combined child_index across all types for bare identifier search
  const globalChildIndex: Array<ChildIndexEntry & { type: string }> = [];
  for (const type of types) {
    for (const [ns, data] of Object.entries(registry[type])) {
      if (!data.match_nodes) continue;
      for (const node of data.match_nodes) {
        const nameSlug = extractNameSlug(node);
        if (!node.children) continue;
        for (const child of node.children) {
          globalChildIndex.push({
            type,
            namespace: ns,
            name_slug: nameSlug,
            patterns: child.patterns,
            description: child.description,
            weight: child.weight,
            has_url: !!child.data?.url,
          });
        }
      }
    }
  }
  entries.push({
    key: "secid",
    value: JSON.stringify({ child_index: globalChildIndex }),
  });
  console.log(`  global child_index: ${globalChildIndex.length} entries`);

  // full:registry — complete compiled registry
  entries.push({
    key: "full:registry",
    value: JSON.stringify(registry),
  });

  // meta:registry — version metadata
  entries.push({
    key: "meta:registry",
    value: JSON.stringify({
      version: new Date().toISOString(),
      total_namespaces: count,
      types: typeCounts,
    }),
  });

  console.log(`Built ${entries.length} KV entries from ${count} namespaces:`);
  for (const type of types) {
    console.log(`  ${type}: ${typeCounts[type]} namespaces`);
  }

  for (const entry of entries) {
    const bytes = Buffer.byteLength(entry.value, "utf8");
    if (bytes > MAX_KV_VALUE_BYTES) {
      throw new Error(
        `KV entry '${entry.key}' is ${bytes} bytes, exceeds ${MAX_KV_VALUE_BYTES} byte (25 MiB) limit.`
      );
    }
  }

  return entries;
}

// ── Upload ──

function upload(entries: BulkEntry[]): void {
  // wrangler kv bulk put expects a JSON array of {key, value} objects
  // There's a 100-entry limit per bulk put, so we batch
  const BATCH_SIZE = 100;
  const tmpDir = join(__dirname, "../.tmp");
  mkdirSync(tmpDir, { recursive: true });

  const namespaceId = preview ? PREVIEW_NS_ID : PRODUCTION_NS_ID;

  for (let i = 0; i < entries.length; i += BATCH_SIZE) {
    const batch = entries.slice(i, i + BATCH_SIZE);
    const tmpFile = join(tmpDir, `kv-batch-${i}.json`);
    writeFileSync(tmpFile, JSON.stringify(batch), "utf-8");

    console.log(
      `Uploading batch ${Math.floor(i / BATCH_SIZE) + 1}/${Math.ceil(entries.length / BATCH_SIZE)} (${batch.length} keys)...`
    );
    execFileSync(
      "npx",
      ["wrangler", "kv", "bulk", "put", tmpFile, "--namespace-id", namespaceId, "--remote"],
      { cwd: join(__dirname, ".."), stdio: "inherit" }
    );
  }

  // Cleanup tmp files
  rmSync(tmpDir, { recursive: true, force: true });
  console.log(
    `\nDone! Uploaded ${entries.length} keys to ${preview ? "preview" : "production"} KV.`
  );
}

// ── Main ──

const entries = buildEntries();
upload(entries);
