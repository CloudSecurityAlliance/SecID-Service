// Registry walk for the MCP output boundary (#67; review-5 F1/F13; plan 0.5).
//
// Builds the MCP output for every source in the real registry (the snapshot
// scripts/build-registry.ts compiles into src/registry.ts, so the pre-deploy
// test run checks the SecID commit being deployed) and fails if registry text
// leaves the `registry_text_untrusted` envelope.
//
// What "leaves the envelope" means here, checked independently of
// src/sanitize.ts (the limits below are this test's own, so loosening the
// sanitizer has to be argued here too):
//   - a key outside the envelope that is not on the allow-list;
//   - a string outside the envelope that contains whitespace and is longer
//     than SPACED_LIMIT (48) characters. Prose needs whitespace; the longest
//     whitespace-containing identifier in today's registry is 36 characters
//     ("LEGGI ED ALTRI ATTI NORMATIVI: 2 (1)"), while the prose fields that
//     used to leak (vendor_recommendation, audit.cli, ...) run to hundreds;
//   - any string outside the envelope longer than TOKEN_LIMIT (128);
//   - a `url` / `wikipedia` that is not an http(s) URL without whitespace;
//   - a control, zero-width or bidi character anywhere, keys included.
// Exempt from the length limits: `secid` (composed by the resolver; must start
// with "secid:"), `pattern` (regex syntax the resolver executes), and the
// service's own top-level `secid_query` / `message`, which echo the caller.
//
// The allow-list below is this test's own copy too. Adding a key to
// STRUCTURAL_KEYS in src/sanitize.ts fails the first test here until the same
// key, with its reason, is added to ALLOWED: a widened allow-list is always a
// visible, reviewed change in two places.
import { describe, it, expect, beforeAll } from "vitest";
import { SELF, env } from "cloudflare:test";
import { seedRegistryKV } from "./helpers/seed-kv";
import { parseSecID } from "../src/parser";
import { resolve, extractNameSlug, patternLiteral } from "../src/resolver";
import { resolveQuery } from "../src/kv-resolve";
import { REGISTRY } from "../src/registry";
import { sanitizeResponseForMcp, STRUCTURAL_KEYS, UNTRUSTED_ENVELOPE_KEY } from "../src/sanitize";
import type { KeyClass } from "../src/sanitize";
import { SECID_TYPES } from "../src/types";
import type { MatchNode } from "../src/types";

const SPACED_LIMIT = 48;
const TOKEN_LIMIT = 128;
// Character classes from code points, so this file stays pure ASCII.
const cls = (ranges: Array<[number, number]>) =>
  ranges.map(([lo, hi]) => `\\u{${lo.toString(16)}}-\\u{${hi.toString(16)}}`).join("");
const WS_RANGES: Array<[number, number]> = [
  [0x09, 0x0d], [0x20, 0x20], [0x85, 0x85], [0xa0, 0xa0], [0x1680, 0x1680],
  [0x2000, 0x200a], [0x2028, 0x2029], [0x202f, 0x202f], [0x205f, 0x205f], [0x3000, 0x3000],
];
const CONTROL_RANGES: Array<[number, number]> = [
  [0x00, 0x08], [0x0b, 0x0c], [0x0e, 0x1f], [0x7f, 0x9f],
  [0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x2064], [0xfeff, 0xfeff],
];
const WHITESPACE = new RegExp(`[${cls(WS_RANGES)}]`, "u");
const CONTROL = new RegExp(`[${cls(CONTROL_RANGES)}]`, "u");
const HTTP_URL = new RegExp(`^https?://[^${cls(WS_RANGES)}]+$`, "iu");
const TOP_LEVEL_SERVICE_KEYS = new Set(["secid_query", "status", "message", "error_id", "subtypes"]);

// Structural keys and their value class, as reviewed for #67 (ADR-020).
const ALLOWED: Record<string, KeyClass> = {
  // resolver-composed SecID; executable regex syntax
  secid: "free", pattern: "free",
  // URLs
  url: "url", wikipedia: "url",
  // identifiers, enums, codes and dates
  namespace: "ident", schema: "ident", wikidata: "ident", version: "ident", label: "ident",
  input: "ident", examples: "ident", available_items: "ident", type: "ident", status: "ident",
  format: "ident", on_match: "ident", lang: "ident", content_type: "ident", parsability: "ident",
  subtype: "ident", subtypes: "ident", country: "ident", release_date: "ident", checked: "ident",
  // containers, counts and flags
  data: "nostring", urls: "nostring", patterns: "nostring", versions_available: "nostring",
  aliases: "nostring", namespaces: "nostring", weight: "nostring", source_count: "nostring",
  child_count: "nostring", namespace_count: "nostring", version_required: "nostring",
};

interface Violation {
  query: string;
  path: string;
  why: string;
  value: string;
}

function codePoints(s: string): number {
  return Array.from(s).length;
}

/** Every way an MCP payload breaks the envelope contract. Empty = clean. */
function envelopeViolations(payload: unknown, query: string): Violation[] {
  const out: Violation[] = [];
  const flag = (path: string, why: string, value: unknown) =>
    out.push({ query, path, why, value: String(value).slice(0, 120) });

  const walk = (v: unknown, path: string, key: string, inEnvelope: boolean): void => {
    if (typeof v === "string") {
      if (CONTROL.test(v)) flag(path, "control/invisible character", v);
      if (inEnvelope) return;
      if (key === "url" || key === "wikipedia") {
        if (!HTTP_URL.test(v)) flag(path, "url outside the envelope is not an http(s) URL", v);
        return;
      }
      if (key === "secid") {
        if (!v.startsWith("secid:")) flag(path, "secid does not start with secid:", v);
        return;
      }
      if (key === "pattern") return;
      const n = codePoints(v);
      if (n > TOKEN_LIMIT) flag(path, `string over ${TOKEN_LIMIT} characters outside the envelope`, v);
      else if (n > SPACED_LIMIT && WHITESPACE.test(v)) flag(path, `spaced string over ${SPACED_LIMIT} characters outside the envelope`, v);
      return;
    }
    if (Array.isArray(v)) {
      v.forEach((x, i) => walk(x, `${path}[${i}]`, key, inEnvelope));
      return;
    }
    if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) {
        if (CONTROL.test(k)) flag(`${path}.${k}`, "control/invisible character in key", k);
        if (k === UNTRUSTED_ENVELOPE_KEY) {
          if (inEnvelope) flag(`${path}.${k}`, "envelope nested inside an envelope", k);
          if (typeof (x as Record<string, unknown>)?._warning !== "string") flag(`${path}.${k}`, "envelope without _warning", k);
          walk(x, `${path}.${k}`, k, true);
          continue;
        }
        if (!inEnvelope && !Object.hasOwn(ALLOWED, k)) flag(`${path}.${k}`, "key outside the envelope is not on the allow-list", k);
        walk(x, `${path}.${k}`, k, inEnvelope);
      }
    }
  };

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    walk(payload, "$", "", false);
    return out;
  }
  for (const [k, v] of Object.entries(payload)) {
    if (k === "results" && Array.isArray(v)) {
      v.forEach((entry, i) => walk(entry, `$.results[${i}]`, "", false));
    } else if (TOP_LEVEL_SERVICE_KEYS.has(k)) {
      // Built by the service: only the control-character rule applies.
      const strings = JSON.stringify(v);
      if (CONTROL.test(strings)) flag(`$.${k}`, "control/invisible character", strings);
    } else {
      flag(`$.${k}`, "unexpected top-level key", k);
    }
  }
  return out;
}

/** One query per source, version, unmatched item and registry example. */
function registryQueries(): string[] {
  const queries: string[] = [];
  for (const [type, namespaces] of Object.entries(REGISTRY)) {
    queries.push(`secid:${type}`);
    for (const [ns, nsData] of Object.entries(namespaces)) {
      queries.push(`secid:${type}/${ns}`);
      for (const node of nsData.match_nodes ?? []) {
        const base = `secid:${type}/${ns}/${patternLiteral(node.patterns[0] ?? "") ?? extractNameSlug(node)}`;
        queries.push(base, `${base}#__no_such_item__`);
        for (const child of node.children ?? []) {
          if (node.data?.version_required) {
            const v = patternLiteral(child.patterns[0] ?? "");
            if (!v) continue;
            queries.push(`${base}@${v}`);
            for (const gc of child.children ?? []) {
              for (const input of exampleInputs(gc)) queries.push(`${base}@${v}#${input}`);
            }
            continue;
          }
          for (const input of exampleInputs(child)) queries.push(`${base}#${input}`, `secid:${type}/${input}`);
        }
      }
    }
  }
  return [...new Set(queries)];
}

function exampleInputs(node: MatchNode): string[] {
  return (node.data?.examples ?? [])
    .map((ex) => (typeof ex === "string" ? ex : ex.input))
    .filter((x): x is string => typeof x === "string" && x.length > 0);
}

describe("MCP output: registry walk (#67)", () => {
  beforeAll(async () => {
    await seedRegistryKV(env.secid_REGISTRY);
  });

  it("the sanitizer's allow-list is exactly the reviewed one", () => {
    expect(Object.fromEntries(STRUCTURAL_KEYS)).toEqual(ALLOWED);
  });

  it("the detector catches the old leaks (unsanitized describe of a capability)", () => {
    const raw = resolve(
      parseSecID("secid:capability/amazon.com/aws/lambda/execution-role", REGISTRY),
      REGISTRY,
    );
    const whys = envelopeViolations(raw, "raw").map((v) => v.why);
    expect(whys).toContain("key outside the envelope is not on the allow-list");
    expect(whys).toContain(`spaced string over ${SPACED_LIMIT} characters outside the envelope`);
  });

  it("keeps registry text inside the envelope for every source, version and example", () => {
    const queries = registryQueries();
    // Sanity: the walk really covers the registry (about 10,000 queries today).
    expect(queries.length).toBeGreaterThan(5000);
    const violations: Violation[] = [];
    for (const q of queries) {
      const out = sanitizeResponseForMcp(resolve(parseSecID(q, REGISTRY), REGISTRY));
      violations.push(...envelopeViolations(out, q));
    }
    expect(violations.slice(0, 20)).toEqual([]);
    expect(violations.length).toBe(0);
  });

  it("keeps registry text inside the envelope on the KV-only paths (root, type listings, bare search)", async () => {
    // seed-kv.ts builds type metadata from TYPE_SHORT_DESCRIPTIONS, not
    // registry/<type>.json (review-5 F20), so purpose/format/examples/notes
    // are not exercised here; SecID-Server-API's walk covers them.
    const queries = [
      "secid:",
      ...SECID_TYPES.map((t) => `secid:${t}`),
      ...SECID_TYPES.map((t) => `secid:${t}/*`),
      "CVE-2021-44228", "cwe", "CWE-79", "T1059", "ismap", "fedramp", "AC-1", "IAM-12", "GHSA-jfh8-c2jp-5v3q",
      "torvalds/linux", "GLI-19", "execution-role", "lambda",
    ];
    const violations: Violation[] = [];
    for (const q of queries) {
      violations.push(...envelopeViolations(sanitizeResponseForMcp(await resolveQuery(env.secid_REGISTRY, q)), q));
    }
    expect(violations.slice(0, 20)).toEqual([]);
  });

  it("keeps registry names inside the envelope in the secid://registry/<type> resources (F13)", async () => {
    const violations: Violation[] = [];
    for (const type of SECID_TYPES) {
      const res = await SELF.fetch("https://test.local/mcp", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "resources/read", params: { uri: `secid://registry/${type}` } }),
      });
      const body = (await res.json()) as { result: { contents: Array<{ text: string }> } };
      const data = JSON.parse(body.result.contents[0].text) as { type: string; namespaces: unknown[] };
      expect(data.namespaces.length).toBeGreaterThan(0);
      violations.push(...envelopeViolations({ results: data.namespaces }, `secid://registry/${type}`));
    }
    expect(violations.slice(0, 20)).toEqual([]);
  });
});
