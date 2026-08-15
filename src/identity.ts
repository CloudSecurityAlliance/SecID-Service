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

/** Lowercased aliases for a namespace, deduped. */
export function namespaceAliases(
  nsKey: string,
  ns: NamespaceIdentity
): string[] {
  const domain = nsKey.split("/")[0];
  const candidates = [domain.split(".")[0], domain];
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
