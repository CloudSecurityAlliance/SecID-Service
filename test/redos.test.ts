import { describe, it, expect } from "vitest";
import { parseSecID } from "../src/parser";
import { resolve, MAX_REGEX_INPUT_CHARS } from "../src/resolver";
import { REGISTRY } from "../src/registry";

// F-03-02: registry regexes run against attacker input with no RE2 / timeout.
// Input is length-capped before matching; an over-long component is treated as
// no-match (not truncated), so valid resolution is unaffected.
describe("ReDoS input bound (F-03-02)", () => {
  it("a valid short identifier still resolves", () => {
    const r = resolve(parseSecID("secid:advisory/mitre.org/cve#CVE-2021-44228", REGISTRY), REGISTRY);
    expect(r.status).toBe("found");
  });

  it("an over-long component does not resolve (skipped before the regex)", () => {
    const long = "A".repeat(MAX_REGEX_INPUT_CHARS + 50);
    const r = resolve(parseSecID(`secid:advisory/${long}`, REGISTRY), REGISTRY);
    expect(r.status).not.toBe("found");
    expect(r.results).toHaveLength(0);
  });
});
