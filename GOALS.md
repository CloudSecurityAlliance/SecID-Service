# SecID-Service — Goals

What `SecID-Service` achieves as the hosted production resolver, remote MCP server, and public web interface for [SecID](https://github.com/CloudSecurityAlliance/SecID), and how we measure success.

## Vision / North Star

Provide a fast, reliable, abuse-resistant, zero-setup public resolution service at [`secid.cloudsecurityalliance.org`](https://secid.cloudsecurityalliance.org) so any human practitioner, automation script, or AI agent can resolve any SecID string via REST (`/api/v1/resolve`), Model Context Protocol (`/mcp`), or browser UI — while continuously feeding unmet demand (`secid_DEMAND`) and user/agent feedback (`secid_FEEDBACK`) back into the registry.

## CSA Goals (Organization)

- **Objective:** Operate an autonomous, zero-downtime edge deployment pipeline that keeps `secid.cloudsecurityalliance.org` synchronized with the authoritative JSON registry in [`CloudSecurityAlliance/SecID`](https://github.com/CloudSecurityAlliance/SecID).
  - **Success metrics:**
    - ≥ 99.5% rolling 90-day availability across `/`, `/api/v1/resolve`, and `/mcp`.
    - 100% of `CloudSecurityAlliance/SecID` `main` merges touching `registry/**/*.json` trigger `registry-kv-upload.yml` so the latest validated registry state is synced to Cloudflare KV (`secid_REGISTRY`), deployed, and verified by the post-deploy Playwright gate within ~3 minutes.
- **Objective:** Capture actionable demand intelligence from real-world resolution traffic and agent feedback to guide registry expansion.
  - **Success metrics:**
    - 100% of eligible unresolved namespace-miss queries (valid domain structure, ≤ 96 bytes per `src/demand.ts`) emitted to Analytics Engine (`secid_DEMAND`) and exportable via `scripts/export-misses.ts`.
    - 100% of `submit_feedback` entries in `secid_FEEDBACK` triaged into registry issues or pull requests.

## Community & Ecosystem Goals

- **Objective:** Deliver a deterministic, spec-conformant REST API (`/api/v1/resolve`) and interactive web documentation (`website/`) that make SecID grammar and all 2,138+ namespaces immediately usable without local setup.
  - **Success metrics:**
    - 100% pass rate on the auto-generated registry example test suite (`test/resolver.test.ts`, `test/parser.test.ts`) and the cross-language live conformance suite in [`SecID-Client-SDK`](https://github.com/CloudSecurityAlliance/SecID-Client-SDK).
    - Core resolution parity between `SecID-Service` (TypeScript/Cloudflare Worker) and [`SecID-Server-API`](https://github.com/CloudSecurityAlliance/SecID-Server-API) (self-hosted Python resolver) across all five `ResponseStatus` values (`found`, `corrected`, `related`, `not_found`, `error`) and `lang` filtering, aside from documented self-hosted API differences.
- **Objective:** Provide a hardened, standards-compliant remote MCP server (`/mcp`) that AI agents can connect to safely.
  - **Success metrics:**
    - 100% of registry-derived prose fields returned by `/mcp` tools (`resolve`, `lookup`, `describe`) recursively sanitized and isolated in `registry_text_untrusted` (`src/sanitize.ts`, verified by `test/sanitize.test.ts`).
    - 100% compliance with the CSA fleet `/mcp` HTTP method gate contract (`src/method-gate.ts`, `test/method-gate.test.ts`, `e2e/mcp.spec.ts`): `405` for non-POST MCP requests, `302` to `/#mcp-setup` only for positively identified browser navigations, `204` for CORS `OPTIONS`, and `501` for unknown methods.

## Shared Goals

- **Objective:** Maintain strict type and subtype parity across the SecID ecosystem (`SecID`, `SecID-Service`, `SecID-Server-API`, `SecID-Client-SDK`).
  - **Success metrics:** Zero drift between `src/type-registry.ts` (`TYPE_REGISTRY`) and `CloudSecurityAlliance/SecID`'s `scripts/validate-type-list.py` and `scripts/validate-subtypes.py` CI gates.

## Notes

- **How to participate:** Open issues or pull requests in [`CloudSecurityAlliance/SecID-Service`](https://github.com/CloudSecurityAlliance/SecID-Service), or submit registry feedback directly via the `/mcp` `submit_feedback` tool. See [`AGENTS.md`](AGENTS.md) and [`REVIEW.md`](REVIEW.md) for development and code review rules.
- **Related documents:** [`BUSINESS-CASE.md`](BUSINESS-CASE.md), [`OPERATIONAL-RESOURCES.md`](OPERATIONAL-RESOURCES.md), [`BACKUP-RESOURCES.md`](BACKUP-RESOURCES.md), [`INTERFACE-RESOURCES.md`](INTERFACE-RESOURCES.md), [`DECISIONS.md`](DECISIONS.md).
- **Review triggers:** Revisit goals semi-annually or when SecID 2.0 content-serving endpoints graduate from design into production.
