# KV Key Scheme Migration + Disclosure Type + Type-Level Data

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Change KV keys to use SecID strings directly (e.g., `secid:advisory` instead of `type:advisory`), add the missing `disclosure` type, and serve type-level metadata for bare type queries.

**Architecture:** The upload script generates KV entries keyed by SecID strings. The KV registry reader maps these keys. The resolver returns type-level JSON data (description, purpose, examples, namespace listing) for bare type queries like `secid:disclosure`. The website makes type names clickable, resolving to the type listing.

**Tech Stack:** TypeScript, Cloudflare Workers, KV, Vitest, Astro (website)

---

### Task 1: Add `disclosure` to SECID_TYPES

**Files:**
- Modify: `src/types.ts:3-11`
- Modify: `test/parser.test.ts` (add disclosure test case)

- [ ] **Step 1: Add disclosure to the types array**

In `src/types.ts`, add `"disclosure"` to the `SECID_TYPES` array:

```typescript
export const SECID_TYPES = [
  "advisory",
  "weakness",
  "ttp",
  "control",
  "disclosure",
  "regulation",
  "entity",
  "reference",
] as const;
```

- [ ] **Step 2: Add a parser test for disclosure type**

In `test/parser.test.ts`, add a test case confirming disclosure is recognized:

```typescript
it("parses disclosure type", () => {
  const result = parseSecID("secid:disclosure/redhat.com/cna", mockRegistry);
  expect(result.type).toBe("disclosure");
});
```

Where `mockRegistry` needs a disclosure entry. Add to the test's mock registry setup:

```typescript
disclosure: {
  "redhat.com": {} as any,
},
```

- [ ] **Step 3: Run tests**

Run: `cd ~/GitHub/CloudSecurityAlliance/SecID-Service && npm test`
Expected: All tests pass, including the new disclosure test.

- [ ] **Step 4: Commit**

```bash
git add src/types.ts test/parser.test.ts
git commit -m "Add disclosure to SECID_TYPES"
```

---

### Task 2: Change KV key scheme in upload script

**Files:**
- Modify: `scripts/upload-registry-kv.ts`

The key mapping changes:

| Old Key | New Key |
|---------|---------|
| `ns:advisory/mitre.org` | `secid:advisory/mitre.org` |
| `type:advisory` | `secid:advisory` |
| `secid` | `secid:*` |
| `full:registry` | `secid:registry` |
| `meta:registry` | `secid:meta` |

- [ ] **Step 1: Update namespace key generation**

In `scripts/upload-registry-kv.ts`, line ~152, change:

```typescript
// OLD
entries.push({
  key: `ns:${type}/${namespace}`,
  value: raw,
});
```

To:

```typescript
// NEW
entries.push({
  key: `secid:${type}/${namespace}`,
  value: raw,
});
```

- [ ] **Step 2: Update type index key generation**

Line ~201, change:

```typescript
// OLD
entries.push({
  key: `type:${type}`,
  value: JSON.stringify(typeIndex),
});
```

To:

```typescript
// NEW
entries.push({
  key: `secid:${type}`,
  value: JSON.stringify(typeIndex),
});
```

- [ ] **Step 3: Update global index key**

Line ~229, change:

```typescript
// OLD
entries.push({
  key: "secid",
  value: JSON.stringify({ child_index: globalChildIndex }),
});
```

To:

```typescript
// NEW
entries.push({
  key: "secid:*",
  value: JSON.stringify({ child_index: globalChildIndex }),
});
```

- [ ] **Step 4: Update full registry key**

Line ~238, change:

```typescript
// OLD
entries.push({
  key: "full:registry",
  value: JSON.stringify(registry),
});
```

To:

```typescript
// NEW
entries.push({
  key: "secid:registry",
  value: JSON.stringify(registry),
});
```

- [ ] **Step 5: Update meta key**

Line ~244, change:

```typescript
// OLD
entries.push({
  key: "meta:registry",
  value: JSON.stringify({ ... }),
});
```

To:

```typescript
// NEW
entries.push({
  key: "secid:meta",
  value: JSON.stringify({ ... }),
});
```

- [ ] **Step 6: Commit**

```bash
git add scripts/upload-registry-kv.ts
git commit -m "Change KV keys to use SecID strings (secid:type/namespace)"
```

---

### Task 3: Update KV registry reader to match new keys

**Files:**
- Modify: `src/kv-registry.ts`
- Modify: `test/kv-resolve.test.ts` (update mock KV keys if needed)

- [ ] **Step 1: Update getTypeIndex key**

In `src/kv-registry.ts`, line 27, change:

```typescript
// OLD
const data = await this.kv.get<TypeIndex>(`type:${type}`, "json");
```

To:

```typescript
// NEW
const data = await this.kv.get<TypeIndex>(`secid:${type}`, "json");
```

- [ ] **Step 2: Update getNamespace key**

Line 38, change:

```typescript
// OLD
const data = await this.kv.get<RegistryNamespace>(`ns:${key}`, "json");
```

To:

```typescript
// NEW
const data = await this.kv.get<RegistryNamespace>(`secid:${key}`, "json");
```

- [ ] **Step 3: Update getNamespaces key (batch fetch)**

Line 62-63, change:

```typescript
// OLD
const data = await this.kv.get<RegistryNamespace>(
  `ns:${type}/${ns}`,
  "json"
);
```

To:

```typescript
// NEW
const data = await this.kv.get<RegistryNamespace>(
  `secid:${type}/${ns}`,
  "json"
);
```

- [ ] **Step 4: Update getGlobalIndex key**

Line 76, change:

```typescript
// OLD
return this.kv.get<GlobalIndex>("secid", "json");
```

To:

```typescript
// NEW
return this.kv.get<GlobalIndex>("secid:*", "json");
```

- [ ] **Step 5: Update getFullRegistry key**

Line 80, change:

```typescript
// OLD
return this.kv.get<Registry>("full:registry", "json");
```

To:

```typescript
// NEW
return this.kv.get<Registry>("secid:registry", "json");
```

- [ ] **Step 6: Update getMeta key**

Line 84, change:

```typescript
// OLD
return this.kv.get<RegistryMeta>("meta:registry", "json");
```

To:

```typescript
// NEW
return this.kv.get<RegistryMeta>("secid:meta", "json");
```

- [ ] **Step 7: Update any KV mock keys in tests**

Check `test/kv-resolve.test.ts` and `test/api.test.ts` — update mock KV stores to use the new key names (`secid:advisory` instead of `type:advisory`, etc.).

- [ ] **Step 8: Run tests**

Run: `cd ~/GitHub/CloudSecurityAlliance/SecID-Service && npm test`
Expected: All tests pass with new key scheme.

- [ ] **Step 9: Commit**

```bash
git add src/kv-registry.ts test/
git commit -m "Update KV reader to use secid: key prefix"
```

---

### Task 4: Enrich TypeIndex with type-level JSON data

**Files:**
- Modify: `scripts/upload-registry-kv.ts`
- Modify: `src/types.ts` (extend TypeIndex)

The SecID repo now has `registry/<type>.json` files with rich metadata (description, purpose, format, examples, notes). The upload script should read these and include the data in the TypeIndex KV entries.

- [ ] **Step 1: Extend TypeIndex type**

In `src/types.ts`, update the `TypeIndex` interface:

```typescript
export interface TypeIndex {
  type: string;
  description: string;
  purpose?: string;
  format?: string;
  examples?: string[];
  notes?: string;
  namespace_count: number;
  namespaces: Array<{
    namespace: string;
    official_name: string;
    common_name: string | null;
    source_count: number;
  }>;
  child_index: ChildIndexEntry[];
}
```

- [ ] **Step 2: Update upload script to read type-level JSON**

In `scripts/upload-registry-kv.ts`, after parsing all namespace files and before building TypeIndex entries (~line 158), add code to read type-level JSON:

```typescript
// Read type-level JSON files (registry/<type>.json) for rich metadata
interface TypeLevelJson {
  type: string;
  official_name: string;
  description: string;
  purpose?: string;
  format?: string;
  examples?: string[];
  notes?: string;
  namespace_count?: number;
}

const typeLevelData: Record<string, TypeLevelJson> = {};
for (const type of types) {
  const typePath = join(registryDir, `${type}.json`);
  try {
    const raw = readFileSync(typePath, "utf-8");
    typeLevelData[type] = JSON.parse(raw);
  } catch {
    // No type-level JSON — use defaults
  }
}
```

Then when building each TypeIndex entry, merge in the type-level data:

```typescript
const tld = typeLevelData[type];
const typeIndex: TypeIndex = {
  type,
  description: tld?.description ?? TYPE_DESCRIPTIONS[type] ?? type,
  purpose: tld?.purpose ?? undefined,
  format: tld?.format ?? undefined,
  examples: tld?.examples ?? undefined,
  notes: tld?.notes ?? undefined,
  namespace_count: namespaces.length,
  namespaces,
  child_index: childIndex,
};
```

- [ ] **Step 3: Run upload in preview mode to verify**

```bash
cd ~/GitHub/CloudSecurityAlliance/SecID-Service
npx tsx scripts/upload-registry-kv.ts --preview
```

Expected: Shows disclosure type in output, type-level data included.

- [ ] **Step 4: Commit**

```bash
git add src/types.ts scripts/upload-registry-kv.ts
git commit -m "Enrich TypeIndex with type-level JSON metadata (purpose, format, examples)"
```

---

### Task 5: Update resolver to return type-level metadata

**Files:**
- Modify: `src/resolver.ts` (update `listNamespaces` function)

- [ ] **Step 1: Update listNamespaces to include type metadata**

The resolver's `listNamespaces` function (line ~74) currently returns just namespace listings. It should also return the type-level metadata. But it receives a `Record<string, RegistryNamespace>` — it doesn't have TypeIndex data.

The fix: in `src/kv-resolve.ts`, for type-only queries, pass the TypeIndex data through. Update the type-only branch (~line 95-100 in `kv-resolve.ts`):

In `kv-resolve.ts`, after the "Type-only query" detection, instead of fetching all namespaces and calling `resolve()`, return a type-level response directly:

```typescript
// Type-only query — return type metadata from TypeIndex
if (!parsed.namespace && !parsed.name) {
  return {
    secid_query: input,
    status: "found",
    results: [{
      secid: `secid:${type}`,
      data: {
        official_name: typeIndex.type,
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
```

This avoids fetching all 486 disclosure namespaces just to list them — the TypeIndex already has the listing.

- [ ] **Step 2: Run tests**

Run: `cd ~/GitHub/CloudSecurityAlliance/SecID-Service && npm test`

- [ ] **Step 3: Commit**

```bash
git add src/kv-resolve.ts
git commit -m "Return type-level metadata for bare type queries (secid:advisory, secid:disclosure)"
```

---

### Task 6: Make type names clickable on website

**Files:**
- Modify: `website/src/pages/index.astro`

- [ ] **Step 1: Wrap type h3 elements in resolver links**

In `website/src/pages/index.astro`, change each type card's `<h3>` from plain text to a link that populates the resolver box. For example, line 87:

```html
<!-- OLD -->
<h3>advisory</h3>

<!-- NEW -->
<h3><a href="javascript:void(0)" onclick="document.getElementById('secid-input').value='secid:advisory';document.getElementById('secid-input').dispatchEvent(new Event('input'))">advisory</a></h3>
```

Or, cleaner — use a data attribute and a small script:

```html
<h3><a href="/resolve?secid=secid:advisory" class="type-link" data-secid="secid:advisory">advisory</a></h3>
```

Apply this to all 8 type cards. The `/resolve` route already exists (line 44 of `index.ts`) and redirects to `/?secid=...`.

- [ ] **Step 2: Style the type links**

In the `<style>` section, add:

```css
.type-card h3 a {
  color: inherit;
  text-decoration: none;
}
.type-card h3 a:hover {
  text-decoration: underline;
}
```

- [ ] **Step 3: Update namespace count in website**

The website currently says "124 namespaces" — update to 616:

Search for `124` in `index.astro` and update to `616`. Also update any "7 types" references to "8 types".

- [ ] **Step 4: Rebuild website**

```bash
cd ~/GitHub/CloudSecurityAlliance/SecID-Service/website
npm run build
```

- [ ] **Step 5: Commit**

```bash
git add website/
git commit -m "Make type names clickable, update counts to 616 namespaces"
```

---

### Task 7: Upload new KV data and purge old keys

**Files:** None (operational task)

- [ ] **Step 1: Upload with new key scheme**

```bash
cd ~/GitHub/CloudSecurityAlliance/SecID-Service
npx tsx scripts/upload-registry-kv.ts
```

Expected: Output shows 8 types including disclosure, 616+ namespaces, keys use `secid:` prefix.

- [ ] **Step 2: Purge old keys**

List old keys and delete them:

```bash
# List old-format keys
wrangler kv key list --namespace-id=cfbc271787614516a39fa43d9ca4f95a | jq -r '.[].name' | grep -E '^(type:|ns:|full:|meta:)' > /tmp/old-keys.txt

# Delete each old key
while read key; do
  wrangler kv key delete "$key" --namespace-id=cfbc271787614516a39fa43d9ca4f95a
done < /tmp/old-keys.txt
```

- [ ] **Step 3: Verify the service works**

```bash
# Type-level query — should return type metadata
curl -s "https://secid.cloudsecurityalliance.org/api/v1/resolve?secid=secid:disclosure" | jq .status
# Expected: "found"

# Namespace query — should still work
curl -s "https://secid.cloudsecurityalliance.org/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228" | jq .status
# Expected: "found"

# Bare identifier — should still work
curl -s "https://secid.cloudsecurityalliance.org/api/v1/resolve?secid=CVE-2021-44228" | jq .status
# Expected: "found"
```

- [ ] **Step 4: Commit (if any cleanup needed)**

---

### Task 8: Deploy worker

- [ ] **Step 1: Deploy**

```bash
cd ~/GitHub/CloudSecurityAlliance/SecID-Service
npx wrangler deploy
```

- [ ] **Step 2: Verify production**

```bash
curl -s "https://secid.cloudsecurityalliance.org/api/v1/resolve?secid=secid:disclosure" | jq .
```

Expected: Returns disclosure type metadata with 486 namespaces listed.

- [ ] **Step 3: Final commit and push**

```bash
git push
```
