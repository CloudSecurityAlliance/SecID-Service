import { describe, it, expect } from "vitest";
import {
  capString,
  FEEDBACK_CATEGORIES,
  MAX_ARRAY_ITEMS,
  MAX_DEPTH,
  MAX_FIELD_CHARS,
  MAX_LISTING_ITEMS,
  MAX_MEMBERS,
  MAX_NODES,
  MAX_OUTPUT_BYTES,
  MESSAGE_POINTER,
  NAMESPACE_STATUSES,
  RESPONSE_STATUSES,
  sanitizeJsonRpcForMcp,
  sanitizeListingForMcp,
  sanitizeRecordForMcp,
  sanitizeResponseForMcp,
  STRIP_RANGES,
  SUBTYPES,
  TRUNCATED,
  URL_FORMATS,
  URL_TYPES,
  VERSION_STATUSES,
} from "../src/sanitize";
import { TYPE_REGISTRY } from "../src/type-registry";
import fixturesText from "./fixtures/mcp-sanitize-fixtures.json?raw";

// Special characters by code point, so this test's source stays pure ASCII.
const ESC = String.fromCodePoint(0x1b);
const ZWSP = String.fromCodePoint(0x200b);
const RLO = String.fromCodePoint(0x202e);
const LRI = String.fromCodePoint(0x2066);

interface FixtureCase {
  name: string;
  fn: "response" | "record" | "listing" | "jsonrpc";
  service_message?: boolean;
  input: unknown;
  expected: unknown;
}
interface FixtureDoc {
  vocabularies: Record<string, unknown>;
  cases: FixtureCase[];
}

/** JSON value with any `text` field that holds JSON compared as parsed JSON. */
function normalize(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      let value: unknown = x;
      if (k === "text" && typeof x === "string") {
        try {
          const parsed = JSON.parse(x);
          if (parsed && typeof parsed === "object") value = parsed;
        } catch {
          // plain text
        }
      }
      Object.defineProperty(out, k, { value: normalize(value), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return v;
}

describe("shared MCP sanitizer fixtures (parity with SecID-Server-API)", () => {
  // Loaded as text so JSON.parse keeps "__proto__" as an own property.
  const doc = JSON.parse(fixturesText) as FixtureDoc;

  it("has cases", () => {
    expect(doc.cases.length).toBeGreaterThanOrEqual(30);
  });

  for (const c of doc.cases) {
    it(c.name, () => {
      const got =
        c.fn === "record"
          ? sanitizeRecordForMcp(c.input)
          : c.fn === "listing"
            ? sanitizeListingForMcp(c.input)
            : c.fn === "jsonrpc"
              ? sanitizeJsonRpcForMcp(c.input)
              : sanitizeResponseForMcp(c.input, { serviceMessage: c.service_message === true });
      expect(normalize(JSON.parse(JSON.stringify(got ?? null)))).toEqual(normalize(c.expected));
    });
  }

  it("declares the same vocabularies and character policy as the fixtures", () => {
    const v = doc.vocabularies;
    expect([...SUBTYPES]).toEqual(v.subtypes);
    expect([...VERSION_STATUSES]).toEqual(v.version_statuses);
    expect([...NAMESPACE_STATUSES]).toEqual(v.namespace_statuses);
    expect([...RESPONSE_STATUSES]).toEqual(v.response_statuses);
    expect([...FEEDBACK_CATEGORIES]).toEqual(v.feedback_categories);
    expect(STRIP_RANGES.map(([lo, hi]) => [lo, hi])).toEqual(v.strip_ranges);
    expect([...URL_TYPES]).toEqual(v.url_types);
    expect([...URL_FORMATS]).toEqual(v.url_formats);
    expect({
      max_field_chars: MAX_FIELD_CHARS, max_array_items: MAX_ARRAY_ITEMS, max_listing_items: MAX_LISTING_ITEMS,
      max_depth: MAX_DEPTH, max_members: MAX_MEMBERS, max_nodes: MAX_NODES, max_output_bytes: MAX_OUTPUT_BYTES,
    }).toEqual(v.budgets);
  });

  it("declares exactly the subtypes in src/type-registry.ts", () => {
    const declared = [...new Set(TYPE_REGISTRY.flatMap((t) => t.subtypes.map((s) => s.value)))].sort();
    expect([...SUBTYPES].sort()).toEqual(declared);
  });
});

describe("sanitizeResponseForMcp (#67)", () => {
  it("moves an unknown registry field into the envelope by default", () => {
    const out = sanitizeResponseForMcp({
      status: "found",
      results: [{ secid: "secid:advisory/x", data: { brand_new_field: "anything", audit: { cli: "rm -rf /" } } }],
    }) as any;
    expect(out.results[0].data.brand_new_field).toBeUndefined();
    expect(out.results[0].data.registry_text_untrusted.audit).toEqual({ cli: "rm -rf /" });
  });

  it("replaces a dynamic message with a pointer and keeps the text in the envelope", () => {
    const out = sanitizeResponseForMcp({ status: "not_found", results: [], message: `Subpath "x${ESC}" not found.` }) as any;
    expect(out.message).toBe(MESSAGE_POINTER);
    expect(out.registry_text_untrusted.message).toBe('Subpath "x" not found.');
  });

  it("moves the echoed query into the envelope, stripped of control, bidi and zero-width characters", () => {
    const out = sanitizeResponseForMcp({ status: "found", results: [], secid_query: `CVE-1${LRI}${RLO}${ZWSP}` }) as any;
    expect(out.secid_query).toBeUndefined();
    expect(out.registry_text_untrusted.secid_query).toBe("CVE-1");
  });

  it("never lets a registry __proto__ key reach the prototype", () => {
    const input = JSON.parse('{"results":[{"secid":"secid:advisory/x","data":{"__proto__":{"polluted":true}}}]}');
    const out = sanitizeResponseForMcp(input) as any;
    const envelope = out.results[0].data.registry_text_untrusted;
    expect(Object.getPrototypeOf(envelope)).toBe(Object.prototype);
    expect(Object.hasOwn(envelope, "__proto__")).toBe(true);
    expect(({} as any).polluted).toBeUndefined();
  });
});

// Bounded cost (review of #68, P2-d). Time limits are generous so CI is not
// flaky; the old Array.from implementation needed ~8 bytes per input
// character on top of the input and blew the isolate's memory here.
describe("capString cost is bounded by its output", () => {
  it("caps a 32 MiB string without materialising it", () => {
    const big = "a".repeat(32 * 1024 * 1024);
    const t0 = Date.now();
    const out = capString(big);
    expect(out.length).toBe(MAX_FIELD_CHARS);
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  it("scans 8 MiB of stripped characters and keeps what follows", () => {
    const big = ZWSP.repeat(8 * 1024 * 1024) + "kept";
    const t0 = Date.now();
    expect(capString(big)).toBe("kept");
    expect(Date.now() - t0).toBeLessThan(5000);
  });

  it("sanitizes a payload with a 16 MiB field", () => {
    const out = sanitizeResponseForMcp({
      status: "found",
      results: [{ secid: "secid:advisory/x", data: { notes: "n".repeat(16 * 1024 * 1024), url: "https://x.example/" } }],
    }) as any;
    expect(out.results[0].data.registry_text_untrusted.notes.length).toBe(MAX_FIELD_CHARS);
    expect(out.results[0].data.url).toBe("https://x.example/");
  });
});

// Budgets (review of #68 round 2, P2): checked before anything is copied.
describe("budgets", () => {
  const marker = { registry_text_untrusted: { _truncated: TRUNCATED, _warning: expect.any(String) } };

  it("a 300,000-member object costs a marker, not a copy", () => {
    const wide: Record<string, string> = {};
    for (let i = 0; i < 300_000; i++) wide[`k${i}`] = "v";
    const t0 = Date.now();
    const out = sanitizeResponseForMcp({ status: "found", results: [{ secid: "secid:advisory/x", data: { known_values: wide } }] }) as any;
    expect(out.results[0]).toEqual(marker);
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  it("200,000 levels of nesting do not overflow the stack", () => {
    let deep: unknown = "x";
    for (let i = 0; i < 200_000; i++) deep = [deep];
    const out = sanitizeResponseForMcp({ status: "found", results: [{ secid: "secid:advisory/x", data: { notes: deep } }] }) as any;
    expect(out.results[0]).toEqual(marker);
    expect(sanitizeResponseForMcp(deep)).toBe(TRUNCATED);
  });

  it("the node budget is cumulative over results, in order", () => {
    const fat = (n: number) => ({ secid: "secid:advisory/x", data: { notes: Array.from({ length: 64 }, () => Array.from({ length: n }, () => 1)) } });
    // Each fat(64) entry is 1 + 1 + 1 + 64 * (1 + 64) = 4,163 values: four fit in 20,000, the fifth does not.
    const out = sanitizeResponseForMcp({ status: "found", results: [fat(64), fat(64), fat(64), fat(64), fat(64), { secid: "secid:advisory/y", weight: 1 }] }) as any;
    expect(out.results.slice(0, 4).every((r: any) => r.secid === "secid:advisory/x")).toBe(true);
    expect(out.results[4]).toEqual(marker);
    expect(out.results[5]).toEqual({ secid: "secid:advisory/y", weight: 1 });
  });

  it("the byte budget is cumulative over results, in order", () => {
    const big = { secid: "secid:advisory/x", data: { notes: Array.from({ length: 40 }, () => "n".repeat(4000)) } };
    // Each entry carries 160,000 bytes of notes: six fit in 1 MiB, the seventh does not.
    const out = sanitizeResponseForMcp({ status: "found", results: Array.from({ length: 8 }, () => big) }) as any;
    expect(out.results.slice(0, 6).every((r: any) => r.secid === "secid:advisory/x")).toBe(true);
    expect(out.results[6]).toEqual(marker);
  });

  it("listings are capped at MAX_LISTING_ITEMS and say so", () => {
    const namespaces = Array.from({ length: MAX_LISTING_ITEMS + 5 }, (_, i) => ({ namespace: `n${i}.example`, source_count: i }));
    const out = sanitizeListingForMcp({ type: "advisory", namespaces }) as any;
    expect(out.namespaces.length).toBe(MAX_LISTING_ITEMS);
    expect(out.registry_text_untrusted._truncated).toBe(TRUNCATED);
  });
});
