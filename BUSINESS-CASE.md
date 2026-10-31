# SecID-Service — Business Case

## Executive summary

`SecID-Service` is the hosted production runtime for SecID at [`secid.cloudsecurityalliance.org`](https://secid.cloudsecurityalliance.org): a single Cloudflare Worker that serves the REST resolver API (`/api/v1/resolve`), the remote Model Context Protocol server (`/mcp`: `resolve`, `lookup`, `describe`, `submit_feedback`), and the public documentation and interactive resolver website (`website/`). Without a zero-setup hosted service, adopting SecID would require every consumer or AI agent to clone and self-host the 2,138-namespace registry; `SecID-Service` reduces time-to-first-resolution for humans, scripts, and AI agents to a single HTTP request or MCP server URL at near-zero marginal infrastructure cost.

## Business benefit categories

- **Brand & Market Position** — Operating an always-on, sub-50ms edge resolver and remote MCP server at `secid.cloudsecurityalliance.org` establishes CSA as live technical infrastructure for the security ecosystem, not only a publisher of static PDF/spreadsheet frameworks.
- **Synergy across CSA Programs** — Provides the live lookup and resolution layer used by CSA's `secid` plugin, CCM/AICM tooling, CNA operations, and mapping workflows, plus a structured demand and feedback loop (`secid_DEMAND` Analytics Engine and `secid_FEEDBACK` KV) that tells the registry what practitioners actually search for.
- **Adoption Flywheel** — The hosted `/mcp` endpoint lets any MCP-capable AI client (Claude Code, Claude Desktop, Cursor, Gemini CLI, custom agents) resolve security identifiers immediately without local installation, turning AI agents into both primary consumers and gap-reporters (`submit_feedback`).

Not directly applicable:

- **Direct Revenue** — `SecID-Service` is free public infrastructure (CC0 / Apache-2.0) that enables downstream CSA programs and products rather than charging per query.

## Stakeholder value propositions

### CSA Value Proposition
- **CSA programs and researchers** get a canonical, high-availability resolution API and MCP server backed by Cloudflare KV (`secid_REGISTRY`), eliminating per-project identifier lookup tables and manual URL construction.
- **SecID governance (`CSA-Internal-Governance/SecID`)** gets real-time telemetry on unresolved identifier misses (`secid_DEMAND`) and structured agent/user submissions (`secid_FEEDBACK`), driving evidence-based registry expansion.

### Community Value Proposition
- **Security practitioners, tool builders, and AI engineers** get a free, unauthenticated REST API (`/api/v1/resolve`) and stateless Streamable HTTP MCP server (`/mcp`) that resolves over 2,100 security namespaces (`cve`, `cwe`, `att&ck`, `nist`, `ccm`, vendor advisories, regulations) into authoritative URLs and structured metadata.
- **Contributors** see their merged registry changes in [`CloudSecurityAlliance/SecID`](https://github.com/CloudSecurityAlliance/SecID) deployed to production automatically within ~2 minutes via `registry-kv-upload.yml` (`repository_dispatch: registry-updated`).

### Shared Value Creation
- **Reference implementation parity:** `SecID-Service` (TypeScript / Cloudflare Workers) and [`SecID-Server-API`](https://github.com/CloudSecurityAlliance/SecID-Server-API) (self-hosted Python) implement the exact same resolution algorithm, type registry (`src/type-registry.ts`), and MCP tool contracts, proving the specification is portable across runtimes.

## AI Enablement

1. **Who becomes more AI-capable because CSA ships this?**
   - **AI agents and LLM workflows** (Claude, Gemini, Codex, custom MCP clients) gain deterministic resolution, discovery, and grammar inspection over security identifiers via the remote `/mcp` server (`resolve`, `lookup`, `describe`, `submit_feedback`) without hallucinating URLs or scraping vendor sites.
   - **Security engineers building agentic workflows** get prompt-injection-hardened MCP responses (`src/sanitize.ts`: `sanitizeResponseForMcp()` strips C0/C1/zero-width/bidi control characters, caps field and array lengths, and isolates third-party contributor prose inside `registry_text_untrusted` with an explicit `_warning`).
2. **Mechanism:**
   - **Both novel-surface creation and friction removal.** The remote `/mcp` server creates a novel, zero-install tool surface for AI agents to navigate security knowledge, while `/api/v1/resolve` removes the friction of integrating dozens of incompatible authority APIs.
3. **Counterfactual:**
   - **"Anyone could, but won't / gap stays indefinitely."** Individual vendors maintain resolvers only for their own advisories; only a neutral steward like CSA has the mandate to host a cross-authority resolver and remote MCP server covering regulations, standards, advisories, weaknesses, and disclosures together.

## Resources, risks, and operational burden assessment

### Operational burden

Detailed runtime architecture and recovery procedures live in [`OPERATIONAL-RESOURCES.md`](OPERATIONAL-RESOURCES.md) and [`BACKUP-RESOURCES.md`](BACKUP-RESOURCES.md).

- **Technical operations:** Hosted on Cloudflare Workers + Cloudflare KV (`secid_REGISTRY`, `secid_OBSERVABILITY`, `secid_FEEDBACK`) + Analytics Engine (`secid_DEMAND`). Automated CI (`ci.yml`) and automated KV sync + deploy + Playwright post-deploy verification (`registry-kv-upload.yml`) require zero manual intervention on routine registry updates.
- **Human / agent operations:** Governed autonomously by the SecID governing agent ([`CSA-Internal-Governance/SecID`](https://github.com/CSA-Internal-Governance/SecID)) with mandatory two-agent cross-vendor code review (`AGENTS.md`, `REVIEW.md`).
- **Total ongoing FTE:** < 0.05 human FTE (autonomous agent operations + edge serverless hosting; infrastructure cost is within Cloudflare's base Workers plan).
- **Automation / minimization strategy:**
  - `CloudSecurityAlliance/SecID` merges trigger `registry-kv-upload.yml` automatically.
  - Pre-deploy Vitest suite (`npm test` inside `workerd`) auto-generates test cases from registry examples; post-deploy Playwright E2E checks (`npm run test:e2e -- --grep-invert @third-party`) verify the live deployment.
  - `--sync` mode in `scripts/upload-registry-kv.ts` enforces a 50-orphan deletion safety threshold to prevent accidental KV wipeouts.
- **Burden-exceeds-value / sunset trigger:** Re-evaluate if monthly Cloudflare infrastructure costs exceed $100/month without corresponding ecosystem adoption, or if maintenance of the custom Worker exceeds 4 hours/week.

### Risks and mitigations

- **Prompt injection via third-party registry prose →** Mitigated by recursive MCP output sanitization (`src/sanitize.ts`) and isolation of `submit_feedback` payloads inside an `untrusted` envelope (`src/feedback.ts`, `schema_version: 2`).
- **Abuse / resource exhaustion on unauthenticated endpoints →** Mitigated by strict input caps (`secid` ≤ 1024 chars, MCP body ≤ 64 KiB on received bytes, JSON-RPC batch ≤ 10 messages, `submit_feedback` rate-limited to 20 writes/min/isolate via `src/write-budget.ts`) and stateless POST-only `/mcp` method gating (`src/method-gate.ts`).
- **Cross-repo deploy breakage when registry examples or version requirements change →** Mitigated by the 4-stage cross-repository release train procedure (`test/resolver-correctness.test.ts`, `test/resolver.test.ts`, and `e2e/website.spec.ts` guards updated before breaking registry changes merge) and post-deploy Playwright verification.

## Success metrics

Tracked in [`GOALS.md`](GOALS.md):
- **Availability & deploy health:** ≥ 99.5% rolling 90-day uptime at `secid.cloudsecurityalliance.org`; 100% of `CloudSecurityAlliance/SecID` `main` merges synced to Cloudflare KV within 3 minutes.
- **Resolver conformance:** 100% pass rate on the Vitest unit suite (`test/`) and live conformance suite ([`SecID-Client-SDK/tests/conformance/`](https://github.com/CloudSecurityAlliance/SecID-Client-SDK)), and zero unmitigated parity drift against `SecID-Server-API`.
- **Feedback & demand loop:** 100% of valid `submit_feedback` submissions in `secid_FEEDBACK` triaged into registry issues or PRs.
