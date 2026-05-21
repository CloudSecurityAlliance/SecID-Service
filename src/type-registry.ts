// ── SecID Type Registry ──
//
// SINGLE SOURCE OF TRUTH for SecID types and their named subtypes.
//
// Imported by Worker code (api.ts, mcp.ts), the homepage (index.astro), and the
// Resolver component (Resolver.astro). When a type or subtype is added, removed,
// or its description changes, this file is the only place that needs editing —
// other code reads from this constant.
//
// IMPORTANT — changes to this file are a big deal:
//   * Adding/removing a type is a spec-level event requiring coordinated changes
//     across SecID, SecID-Service, SecID-Server-API, and SecID-Client-SDK.
//   * Adding a subtype is a registry-level event requiring a corresponding
//     SecID PR that updates docs/reference/TYPES-AND-SUBTYPES.md.
//   * The SecID repo's CI validates that every `subtype:` value used in
//     registry data is declared here. Drift is caught at PR time.
//
// See SecID's docs/reference/TYPES-AND-SUBTYPES.md for the conceptual model.

export interface SubtypeDef {
  /** The canonical kebab-case value used in registry data's `data.subtype` array. */
  value: string;
  /** One-sentence description for display in describe responses and the API. */
  description: string;
}

export interface TypeDef {
  /** Type name (matches the value in registry entries' `type` field). */
  type: string;
  /** Short human description for the homepage type card and resolver views. */
  short: string;
  /** Longer description used by the MCP describe tool. */
  long: string;
  /** Named subtypes declared for this type. Empty array if none. */
  subtypes: readonly SubtypeDef[];
}

// Order is intentional — matches the visual ordering in registry/INDEX.md and
// the homepage type-card grid.
export const TYPE_REGISTRY: readonly TypeDef[] = [
  {
    type: "advisory",
    short: "Vulnerability publications — CVEs, vendor advisories, GHSAs, incident reports",
    long: "Publications about vulnerabilities — CVE records, GHSA advisories, vendor advisories, and incident reports (AIID, NHTSA, FDA adverse events). Both vuln advisories and incident reports answer 'this happened.'",
    subtypes: [],
  },
  {
    type: "capability",
    short: "Product security features — AWS encryption, CloudTrail, Azure RBAC",
    long: "Concrete product security features with configuration options, audit commands, and remediation instructions. Vendor-authoritative facts about what a product can do.",
    subtypes: [],
  },
  {
    type: "control",
    short: "Security requirements — NIST CSF, ISO 27001, CCM, CIS Benchmarks",
    long: "Normative security requirements — frameworks (NIST CSF, ISO 27001), control catalogs (CCM, AICM), benchmarks (CIS, HarmBench), and documentation standards (Model Cards). Defines what must be done or tested.",
    subtypes: [],
  },
  {
    type: "disclosure",
    short: "Vulnerability disclosure programs, policies, reporting channels",
    long: "Vulnerability disclosure programs — CVE Numbering Authorities, PSIRTs, bug bounty programs, security.txt entries, and policy documents. Tells researchers how and where to report.",
    subtypes: [],
  },
  {
    type: "entity",
    short: "Organizations, products, services",
    long: "Organizations (Microsoft, NIST, ISO), products (Office 365, AWS S3), and services. Identity records — cited as anchors by other types.",
    subtypes: [],
  },
  {
    type: "methodology",
    short: "Formal processes — scoring, mapping, risk assessment, threat modeling",
    long: "Formal processes with defined inputs, steps, and outputs — methodologies for scoring (CVSS, SSVC, EPSS), mapping (IR 8477, CTID), risk management (FAIR, ISO 27005), threat modeling (STRIDE, PASTA), and more.",
    subtypes: [
      { value: "mapping", description: "Methodologies that produce a mapping/crosswalk from one framework to another." },
      { value: "scoring", description: "Methodologies that produce a score, prioritization decision, or rating." },
      { value: "risk-management", description: "Methodologies for identifying, analyzing, evaluating, and treating risk." },
      { value: "vulnerability-management", description: "Methodologies for receiving, handling, and disclosing vulnerabilities." },
      { value: "threat-modeling", description: "Methodologies for systematically identifying threats against a system." },
      { value: "security-testing", description: "Methodologies for conducting security tests and assessments." },
      { value: "digital-forensics", description: "Methodologies for digital evidence collection, preservation, and analysis." },
      { value: "incident-management", description: "Methodologies for detecting, handling, and analyzing security incidents." },
      { value: "supply-chain", description: "Methodologies for software supply chain security." },
      { value: "audit-certification", description: "Methodologies for conformity assessment and certification." },
      { value: "classification", description: "Methodologies for classifying or labeling information for handling (e.g., TLP)." },
    ],
  },
  {
    type: "reference",
    short: "Documents, research, identifier systems — arXiv, DOI, RFCs, CSA artifacts",
    long: "Documents, research papers, and identifier systems — arXiv, DOI, ISBN, RFCs, and CSA artifacts. Citation targets without normative force.",
    subtypes: [
      { value: "glossary", description: "A glossary document with addressable term-level subpaths. Entry is identity-only; term data lives in a separate dataset repository." },
    ],
  },
  {
    type: "regulation",
    short: "Laws and legal requirements — GDPR, HIPAA, PCI DSS",
    long: "Laws, directives, and binding legal requirements — GDPR, HIPAA, NIS2, PSD2, and national transpositions of EU directives.",
    subtypes: [],
  },
  {
    type: "ttp",
    short: "Adversary techniques — MITRE ATT&CK, ATLAS, CAPEC",
    long: "Tactics, techniques, and procedures used by adversaries — MITRE ATT&CK (enterprise, mobile, ICS), ATLAS (AI attacks), and CAPEC.",
    subtypes: [],
  },
  {
    type: "weakness",
    short: "Abstract flaw patterns — CWE, OWASP Top 10",
    long: "Abstract weakness patterns — Common Weakness Enumeration (CWE) and OWASP Top 10 categories. Not specific vulnerabilities; classes of flaws.",
    subtypes: [],
  },
] as const;

// ── Derived helpers ──

/** All 10 SecID type names in canonical order. */
export const SECID_TYPES = TYPE_REGISTRY.map((t) => t.type) as readonly string[];

/** Type alias — restrictive string union over the 10 declared types. */
export type SecIDType = (typeof TYPE_REGISTRY)[number]["type"];

/** Lookup map by type name. Returns undefined for unknown types. */
export const TYPE_BY_NAME: Readonly<Record<string, TypeDef | undefined>> = Object.fromEntries(
  TYPE_REGISTRY.map((t) => [t.type, t]),
);

/** All valid subtype values, keyed by type name. Used by CI validation. */
export const SUBTYPES_BY_TYPE: Readonly<Record<string, readonly string[]>> = Object.fromEntries(
  TYPE_REGISTRY.map((t) => [t.type, t.subtypes.map((s) => s.value)]),
);

/** Short-description-only map. Used by homepage cards and Resolver TYPE_DESCRIPTIONS. */
export const TYPE_SHORT_DESCRIPTIONS: Readonly<Record<string, string>> = Object.fromEntries(
  TYPE_REGISTRY.map((t) => [t.type, t.short]),
);
