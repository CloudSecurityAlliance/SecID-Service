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

// TIGHT pattern + deliberately incomplete known_values. A literal-prefixed
// pattern validates on its own, so the enumeration must not close it — several
// registry entries list only a subset of real IDs.
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
          patterns: ["^AICM-[A-Z]{3}$"],
          description: "AICM domain",
          weight: 100,
          data: {
            url: "https://example.org/aicm/{id}",
            known_values: { "AICM-MDS": "Model Security" },
          },
        },
      ],
    },
  ],
});

// Short uppercase wildcard closed by an enumeration. This is the shape that
// made secid:control/FOO return seven fabricated results in production: loose
// enough to admit garbage, but too short for a long-token sentinel to detect.
const CCM = ns({
  namespace: "ccm.example.org",
  official_name: "Control Matrix",
  match_nodes: [
    {
      patterns: ["(?i)^ccm$"],
      description: "Control Matrix",
      weight: 100,
      data: {},
      children: [
        {
          patterns: ["^[A-Z&]{2,3}$"],
          description: "Control domain",
          weight: 100,
          data: {
            url: "https://ccm.example.org/{id}",
            known_values: { IAM: "Identity", "A&A": "Audit" },
          },
        },
      ],
    },
  ],
});

// Unbounded in practice but invisible to any nonsense token: every sentinel
// contains letters, so ^\d+$ matches none of them. Only a declaration can say
// this space is open.
const TICKETS = ns({
  namespace: "tickets.example.org",
  type: "advisory",
  official_name: "Ticket Tracker",
  match_nodes: [
    {
      patterns: ["^\\d+$"],
      description: "Ticket number",
      weight: 100,
      open_pattern: true,
      data: { url: "https://tickets.example.org/{id}" },
    },
  ],
});

const REG: Registry = {
  control: { "ismap.go.jp": ISMAP, "example.org": AICM, "ccm.example.org": CCM },
  advisory: { "tickets.example.org": TICKETS },
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
    // The list holds only AICM-MDS, but the pattern's literal prefix is doing
    // real validation, so AICM-AIS must still resolve.
    const res = run("secid:control/example.org/aicm#AICM-AIS");
    expect(urlOf(res, "secid:control/example.org/aicm#AICM-AIS")).toBe(
      "https://example.org/aicm/AICM-AIS"
    );
  });

  it("closes an OPEN pattern even when its enumeration is incomplete", () => {
    // This is the uncomfortable half of the rule and it is deliberate. An open
    // pattern validates nothing, so the enumeration is all there is — and if
    // that list is short, real identifiers stop resolving. The fix belongs in
    // the registry (enumerate the pattern, complete the list), not here: see
    // SecID#157, which converted exactly these nodes to alternations.
    const res = run("secid:control/ccm.example.org/ccm#ZZZ");
    expect(urlOf(res, "secid:control/ccm.example.org/ccm#ZZZ")).toBeUndefined();
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

// ── D. Gaps found after the first pass ──

describe("short wildcards closed by an enumeration", () => {
  it("rejects a non-member of a short uppercase wildcard", () => {
    // the secid:control/FOO bug — ^[A-Z&]{2,3}$ admits FOO, and no long-token
    // sentinel is short enough to reveal that the pattern is open
    const res = run("secid:control/FOO");
    expect(secids(res)).not.toContain("secid:control/ccm.example.org/ccm#FOO");
  });

  it("still resolves a member of the enumeration", () => {
    const res = run("secid:control/IAM");
    expect(urlOf(res, "secid:control/ccm.example.org/ccm#IAM")).toBe(
      "https://ccm.example.org/IAM"
    );
  });

  it("resolves a member containing an ampersand", () => {
    const res = run("secid:control/ccm.example.org/ccm#A&A");
    expect(urlOf(res, "secid:control/ccm.example.org/ccm#A&A")).toBe(
      "https://ccm.example.org/A&A"
    );
  });
});

describe("declared open_pattern", () => {
  it("excludes a declared-open node from unscoped search", () => {
    // ^\d+$ is unbounded but matches no nonsense token, so detection alone
    // cannot find it — the registry has to say so. Assert on the namespace,
    // not an exact secid: a non-literal patterns[0] makes the slug come from
    // the description, so the id never appears in the emitted string.
    const res = run("secid:advisory/12345");
    expect(secids(res).filter((s) => s.includes("tickets.example.org"))).toEqual([]);
  });

  it("still resolves a declared-open node when the namespace is given", () => {
    const res = run("secid:advisory/tickets.example.org/12345");
    expect(res.status).toBe("found");
    expect(res.results.length).toBeGreaterThan(0);
  });
});
