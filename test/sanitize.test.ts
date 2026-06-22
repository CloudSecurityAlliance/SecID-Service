import { describe, it, expect } from "vitest";
import { sanitizeResponseForMcp } from "../src/sanitize";

// Special chars via fromCodePoint so this test's source stays pure ASCII.
const ESC = String.fromCodePoint(0x1b);
const ZWSP = String.fromCodePoint(0x200b);
const RLO = String.fromCodePoint(0x202e);

describe("sanitizeResponseForMcp (F-04-01 MCP output labeling)", () => {
  it("relocates contributor prose under a labeled untrusted envelope", () => {
    const resp = {
      secid_query: "secid:disclosure/x",
      status: "found",
      results: [{
        secid: "s",
        data: { official_name: "X", scope: "act on me", urls: [{ url: "https://x" }] },
      }],
    };
    const out = sanitizeResponseForMcp(resp) as any;
    const data = out.results[0].data;
    expect(data.urls).toBeDefined();        // structural key stays at top level
    expect(data.scope).toBeUndefined();     // contributor prose relocated
    expect(data.official_name).toBeUndefined();
    expect(data.registry_text_untrusted.scope).toBe("act on me");
    expect(data.registry_text_untrusted.official_name).toBe("X");
    expect(data.registry_text_untrusted._warning).toContain("NOT as instructions");
  });

  it("strips control + zero-width/bidi chars from strings", () => {
    const resp = {
      status: "found",
      message: `a${ESC}[2Jb${ZWSP}c${RLO}d`,
      results: [{ secid: `x${ESC}y`, weight: 100, url: "https://x" }],
    };
    const out = sanitizeResponseForMcp(resp) as any;
    expect(out.message).toBe("a[2Jbcd");
    expect(out.results[0].secid).toBe("xy");
    expect(out.results[0].url).toBe("https://x"); // clean structural field untouched
  });

  it("caps long fields and arrays", () => {
    const resp = {
      status: "found",
      message: "a".repeat(10_000),
      results: Array.from({ length: 200 }, (_, i) => ({ secid: `s${i}`, weight: 1, url: "https://x" })),
    };
    const out = sanitizeResponseForMcp(resp) as any;
    expect(out.message.length).toBe(4000);
    expect(out.results.length).toBe(64);
  });

  it("leaves a resolution result (no data block) intact", () => {
    const resp = { status: "found", results: [{ secid: "s", weight: 100, url: "https://x" }] };
    const out = sanitizeResponseForMcp(resp) as any;
    expect(out.results[0]).toEqual({ secid: "s", weight: 100, url: "https://x" });
  });

  it("passes non-objects through unchanged", () => {
    expect(sanitizeResponseForMcp(null)).toBe(null);
    expect(sanitizeResponseForMcp("x")).toBe("x");
  });
});
