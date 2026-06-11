import { describe, it, expect } from "vitest";
import { parseSecID } from "../src/parser";
import { resolve, buildSubmissionUrl } from "../src/resolver";
import { REGISTRY } from "../src/registry";

function resolveSecID(input: string) {
  return resolve(parseSecID(input, REGISTRY), REGISTRY);
}

const FAKE = "definitely-not-registered-zzz.example";

describe("submission_url on namespace-level miss", () => {
  it("entity miss -> prefilled add-entity form (domain)", () => {
    const r = resolveSecID(`secid:entity/${FAKE}`);
    expect(r.status).toBe("not_found");
    expect(r.submission_url).toBeDefined();
    expect(r.submission_url).toContain("template=add-entity.yml");
    expect(r.submission_url).toContain(`domain=${FAKE}`);
  });

  it("non-entity miss -> prefilled add-namespace form (namespace)", () => {
    const r = resolveSecID(`secid:advisory/${FAKE}/alerts#X-1`);
    expect(r.status).toBe("not_found");
    expect(r.submission_url).toBeDefined();
    expect(r.submission_url).toContain("template=add-namespace.yml");
    expect(r.submission_url).toContain(`namespace=${FAKE}`);
  });

  it("a successful resolution carries no submission_url", () => {
    const r = resolveSecID("secid:advisory/mitre.org/cve#CVE-2021-44228");
    expect(r.status).toBe("found");
    expect(r.submission_url).toBeUndefined();
  });
});

describe("buildSubmissionUrl", () => {
  it("percent-encodes the namespace", () => {
    const url = buildSubmissionUrl("advisory", "ex ample.com/path");
    expect(url).toContain("namespace=ex%20ample.com%2Fpath");
  });
});
