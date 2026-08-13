import { describe, it, expect } from "vitest";
import { parseSecID } from "../src/parser";
import { resolve } from "../src/resolver";
import type {
  Registry,
  RegistryNamespace,
  ResolveResponse,
  ResolutionResult,
  ResultEntry,
} from "../src/types";

// Synthetic fixtures — deliberately NOT the bundled registry, so these tests
// assert search *behaviour* and stay stable as registry data changes.

function ns(over: Partial<RegistryNamespace> & Pick<RegistryNamespace, "namespace">): RegistryNamespace {
  return {
    schema_version: "1.0",
    type: "control",
    status: "published",
    status_notes: null,
    official_name: over.namespace,
    common_name: null,
    alternate_names: null,
    notes: null,
    wikidata: null,
    wikipedia: null,
    urls: [],
    match_nodes: [],
    ...over,
  } as RegistryNamespace;
}

const ISMAP = ns({
  namespace: "ismap.go.jp",
  official_name: "Information system Security Management and Assessment Program",
  common_name: "ISMAP",
  alternate_names: ["ISMAP-CSM"],
  urls: [{ type: "website", url: "https://www.ismap.go.jp/" }],
  match_nodes: [
    {
      patterns: ["(?i)^control-criteria$"],
      description: "Control Criteria of ISMAP",
      weight: 100,
      data: { url: "https://www.ismap.go.jp/criteria" },
    },
  ],
});

// Open pattern + a complete enumeration: known_values is the only real gate.
const CSA = ns({
  namespace: "cloudsecurityalliance.org",
  type: "reference",
  official_name: "Cloud Security Alliance",
  common_name: "CSA",
  match_nodes: [
    {
      patterns: ["(?i)^artifacts$"],
      description: "CSA artifacts",
      weight: 100,
      data: {},
      children: [
        {
          patterns: ["^-?[a-z0-9]([a-z0-9-]*[a-z0-9])?$"],
          description: "Artifact slug",
          weight: 100,
          data: {
            url: "https://cloudsecurityalliance.org/artifacts/{id}",
            known_values: { "ccsk-v5-prep-kit": "CCSK v5 Prep Kit" },
          },
        },
      ],
    },
  ],
});

// Open pattern, genuinely unbounded ID space, no enumeration possible.
const GITHUB_USERS = ns({
  namespace: "github.com/users",
  type: "reference",
  official_name: "GitHub Users",
  match_nodes: [
    {
      patterns: ["^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$"],
      description: "GitHub username or organization name",
      weight: 100,
      data: { url: "https://github.com/{id}" },
    },
  ],
});

// Tight pattern + deliberately INCOMPLETE known_values (mirrors CSA AICM,
// which lists 1 of ~18 domains). The regex must stay authoritative here.
const AICM = ns({
  namespace: "example.org",
  official_name: "AICM Example",
  match_nodes: [
    {
      patterns: ["(?i)^aicm$"],
      description: "AI Controls Matrix",
      weight: 100,
      data: {},
      children: [
        {
          patterns: ["^[A-Z&]{2,3}$"],
          description: "AICM domain",
          weight: 100,
          data: {
            url: "https://example.org/aicm/{id}",
            known_values: { MDS: "Model Security" },
          },
        },
      ],
    },
  ],
});

const REG: Registry = {
  control: { "ismap.go.jp": ISMAP, "example.org": AICM },
  reference: { "cloudsecurityalliance.org": CSA, "github.com/users": GITHUB_USERS },
} as unknown as Registry;

function run(input: string): ResolveResponse {
  return resolve(parseSecID(input, REG), REG);
}

const secids = (r: ResolveResponse): string[] =>
  r.results.map((x: ResultEntry) => (x as { secid: string }).secid);

const urlOf = (r: ResolveResponse, secid: string): string | undefined =>
  (r.results.find((x) => (x as { secid: string }).secid === secid) as ResolutionResult | undefined)?.url;

// ── A. Namespace identity fields are searchable ──

describe("cross-source search matches namespace identity fields", () => {
  it("finds a namespace by its common_name", () => {
    const res = run("secid:control/ismap");
    expect(secids(res)).toContain("secid:control/ismap.go.jp");
  });

  it("finds a namespace by its leading domain label", () => {
    // 'example' is the leading label of example.org
    const res = run("secid:control/example");
    expect(secids(res)).toContain("secid:control/example.org");
  });

  it("finds a namespace by an alternate_name", () => {
    const res = run("secid:control/ISMAP-CSM");
    expect(secids(res)).toContain("secid:control/ismap.go.jp");
  });

  it("matches identity fields case-insensitively", () => {
    expect(secids(run("secid:control/IsMaP"))).toContain("secid:control/ismap.go.jp");
  });

  it("carries the namespace website as the resolved URL", () => {
    expect(urlOf(run("secid:control/ismap"), "secid:control/ismap.go.jp")).toBe(
      "https://www.ismap.go.jp/"
    );
  });

  it("does not match an unrelated word against identity fields", () => {
    // substring/token matching would make 'security' hit ISMAP's official_name
    const res = run("secid:control/security");
    expect(secids(res)).not.toContain("secid:control/ismap.go.jp");
  });

  it("still finds a source by its own name", () => {
    // regression guard: existing source-name behaviour must survive
    expect(secids(run("secid:control/control-criteria"))).toContain(
      "secid:control/ismap.go.jp/control-criteria"
    );
  });
});

// ── B. known_values closes an otherwise-open pattern ──

describe("known_values enforcement", () => {
  it("rejects a non-member when the pattern is open", () => {
    const res = run("secid:reference/ismap");
    expect(secids(res)).not.toContain(
      "secid:reference/cloudsecurityalliance.org/artifacts#ismap"
    );
  });

  it("still resolves a member of the enumeration", () => {
    const res = run("secid:reference/cloudsecurityalliance.org/artifacts#ccsk-v5-prep-kit");
    expect(urlOf(res, "secid:reference/cloudsecurityalliance.org/artifacts#ccsk-v5-prep-kit")).toBe(
      "https://cloudsecurityalliance.org/artifacts/ccsk-v5-prep-kit"
    );
  });

  it("leaves a tight pattern authoritative when known_values is incomplete", () => {
    // AICM lists only MDS but the real matrix has ~18 domains; AIS must resolve.
    const res = run("secid:control/example.org/aicm#AIS");
    expect(urlOf(res, "secid:control/example.org/aicm#AIS")).toBe(
      "https://example.org/aicm/AIS"
    );
  });
});

// ── C. Unbounded patterns are excluded from unscoped search only ──

describe("open patterns in cross-source search", () => {
  it("does not let an unbounded source pattern match a free-text query", () => {
    const res = run("secid:reference/ismap");
    expect(secids(res)).not.toContain(
      "secid:reference/github.com/users/github-username-or-organization-name"
    );
  });

  it("still resolves an unbounded pattern when the namespace is given", () => {
    const res = run("secid:reference/github.com/users/torvalds");
    expect(res.status).toBe("found");
    expect(res.results.length).toBeGreaterThan(0);
  });

  it("does not fabricate a match for an arbitrary identifier", () => {
    // the ^.+$ class of bug: a CVE id must not resolve as a control
    const res = run("secid:control/CVE-2021-44228");
    expect(res.status).toBe("not_found");
  });
});
