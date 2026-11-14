import { describe, it, expect } from "vitest";
import {
  capString,
  FEEDBACK_CATEGORIES,
  MAX_FIELD_CHARS,
  MESSAGE_POINTER,
  NAMESPACE_STATUSES,
  RESPONSE_STATUSES,
  sanitizeJsonRpcForMcp,
  sanitizeRecordForMcp,
  sanitizeResponseForMcp,
  STRIP_RANGES,
  SUBTYPES,
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
  fn: "response" | "record" | "jsonrpc";
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
          ? sanitizeRecordForMcp(c.input as Record<string, unknown>)
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

  it("strips control, bidi (incl. isolates) and zero-width characters from top-level strings", () => {
    const out = sanitizeResponseForMcp({ status: "found", results: [], secid_query: `CVE-1${LRI}${RLO}${ZWSP}` }) as any;
    expect(out.secid_query).toBe("CVE-1");
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
