/**
 * Namespace identity — the strings a namespace can be found by in free-text
 * search.
 *
 * A source slug is often not the name anyone would type. `ismap.go.jp`'s only
 * source is called `control-criteria`, so before identity search existed the
 * namespace was reachable only by a slug a user had no way to guess, while
 * every unrelated namespace with a permissive pattern matched "ismap" happily.
 *
 * Matching is exact and case-insensitive. Substring or token matching over
 * `official_name` was considered and rejected: a term like "security" appears
 * in hundreds of official names and would recreate the noise this fixes.
 *
 * Single definition, imported by the resolver, the KV search path, the upload
 * script, and the test seed — the index and the matcher must never disagree
 * about what an alias is.
 */

export interface NamespaceIdentity {
  official_name?: string | null;
  common_name?: string | null;
  alternate_names?: string[] | null;
}

/**
 * Second-level labels that are part of a public suffix rather than a name —
 * the `go` in `ismap.go.jp`, the `gov` in `uidai.gov.in`, the `co` in a
 * `co.uk`. The final label (the TLD) is always dropped, so this list only
 * needs the second-level cases.
 *
 * Dropping these is what makes label indexing safe. Across the registry `com`
 * appears in 707 namespaces, `org` in 171 and `gov` in 93 — indexing them
 * would make a single query match most of the registry, which is the failure
 * this whole search-quality effort exists to remove.
 */
const PUBLIC_SUFFIX_LABELS = new Set([
  "co", "com", "org", "net", "gov", "edu", "ac", "go", "or", "ne", "gr", "lg",
  "gob", "gouv", "govt", "mil", "int",
]);

/**
 * Lowercased aliases for a namespace, deduped.
 *
 * Every domain label except public-suffix components, every path segment, the
 * full domain, and the declared names. `aws.amazon.com` is findable by `aws`
 * and `amazon`; `amazon.com/aws/s3` by `aws` and `s3`, which are otherwise
 * unsearchable — 68 namespaces carry a path segment.
 *
 * Matching stays exact and token-based. Substring matching was considered and
 * rejected: `security` as a token matches 11 namespaces, but as a substring it
 * would also hit `cloudsecurityalliance.org` and `security-tracker.debian.org`,
 * reintroducing the noise that made searching "ismap" return 19 results.
 */
export function namespaceAliases(
  nsKey: string,
  ns: NamespaceIdentity
): string[] {
  const [domain, ...pathSegments] = nsKey.split("/");

  const labels = domain.split(".");
  // The last label is always a TLD, so it never survives. The FIRST label is
  // always kept, even when it looks like a suffix: it is the namespace's
  // identity. go.dev is the Go project, gov.uk is the UK government, and
  // nic.gov.sa is Saudi Arabia's National Information Center — stripping their
  // leading label would leave them findable only by full domain. The stoplist
  // therefore applies to middle labels only, which is where the damage was:
  // `gov` occurs in 93 namespaces, nearly all as the middle of x.gov.tld.
  const meaningful = labels
    .slice(0, -1)
    .filter((l, i) => l && (i === 0 || !PUBLIC_SUFFIX_LABELS.has(l.toLowerCase())));

  const candidates = [...meaningful, domain, ...pathSegments];
  if (ns.common_name) candidates.push(ns.common_name);
  if (ns.official_name) candidates.push(ns.official_name);
  if (ns.alternate_names) candidates.push(...ns.alternate_names);

  const seen = new Set<string>();
  for (const c of candidates) {
    if (typeof c === "string" && c.trim()) seen.add(c.trim().toLowerCase());
  }
  return [...seen];
}

/** Does `input` name this namespace? */
export function matchesNamespaceIdentity(
  nsKey: string,
  ns: NamespaceIdentity,
  input: string
): boolean {
  const needle = input.trim().toLowerCase();
  if (!needle) return false;
  return namespaceAliases(nsKey, ns).includes(needle);
}
