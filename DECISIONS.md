# Architecture Decision Records

Sequential log of decisions for SecID-Service.

---

## ADR-001: Cloudflare Workers as runtime

**Date:** 2025-02-01 (approx, from initial scaffolding)
**Status:** Accepted
**Decision method:** Human directive

**Goal:** Deploy a globally distributed, low-latency API for resolving SecID strings.

**Context:** SecID needs a lightweight API that's fast worldwide. The service is stateless (reads registry data, returns URLs). No database, no auth, no sessions.

**Decision:** Use Cloudflare Workers as the runtime platform.

**Rationale:** Edge deployment gives low latency globally. Workers' pricing model (CPU time, not duration) is ideal for a service that's mostly I/O-bound (KV reads). Free tier is generous (10M requests/month). Same platform hosts the static website via Workers Assets.

**Rejected alternatives:**
- **AWS Lambda + CloudFront** — More complex setup, cold starts, higher cost at low volume
- **Traditional VPS** — Single region, ops burden, no auto-scaling

---

## ADR-002: Hono as HTTP framework

**Date:** 2025-02-01 (approx, from initial scaffolding)
**Status:** Accepted
**Decision method:** AI default

**Goal:** Route HTTP requests in the Worker with minimal overhead.

**Context:** Need a lightweight router that works natively on Cloudflare Workers (Web Standards API, not Node.js).

**Decision:** Use Hono for HTTP routing.

**Rationale:** Hono is purpose-built for edge runtimes, tiny (~96 KB bundled), fast, and has first-class Cloudflare Workers support. TypeScript native.

**Rejected alternatives:**
- **itty-router** — Even smaller but less mature ecosystem
- **Raw fetch handler** — No routing abstraction, harder to maintain as endpoints grow

---

## ADR-003: Official MCP SDK for MCP server

**Date:** 2025-02-01 (approx, from initial implementation)
**Status:** Accepted
**Decision method:** AI default

**Goal:** Expose SecID as an MCP server so AI assistants can resolve security identifiers.

**Context:** MCP is the emerging standard for AI tool integration. Need to implement the Streamable HTTP transport for remote MCP servers on Cloudflare Workers.

**Decision:** Use `@modelcontextprotocol/sdk` with `WebStandardStreamableHTTPServerTransport`.

**Rationale:** Official SDK ensures protocol compliance and will track spec changes. The `WebStandardStreamableHTTPServerTransport` works directly on Workers without Node.js compatibility. Tool parameter schemas are defined with zod as the SDK requires.

**Rejected alternatives:**
- **Custom MCP implementation** — Protocol is complex (JSON-RPC, SSE, session management). Rolling our own would be fragile and drift from the spec.

---

## ADR-004: Astro for static website

**Date:** 2025-02-15 (approx, from website addition)
**Status:** Accepted
**Decision method:** AI default

**Goal:** Serve a documentation and demo website from the same Worker.

**Context:** Need a static site with the interactive resolver component. Served via Cloudflare Workers Assets (same deployment).

**Decision:** Use Astro to generate the static site, served from `website/dist/` via Workers Assets.

**Rationale:** Astro produces zero-JS static HTML by default, with islands for interactive components. The resolver is a `<script>` tag in an Astro component — no React/Vue runtime needed. Build output is plain HTML/CSS/JS.

**Rejected alternatives:**
- **Plain HTML** — Harder to maintain as pages grow, no component reuse
- **Next.js/Nuxt** — Overkill for a mostly-static site, heavier build output

---

## ADR-005: Bundled in-memory registry → KV-backed registry

**Date:** 2025-03-05
**Status:** Accepted
**Decision method:** Collaborative

**Goal:** Decouple registry data updates from Worker code deployments.

**Context:** The registry was compiled into `src/registry.ts` at build time — a giant TypeScript object bundled into the Worker. Every registry update (new namespace, pattern fix) required rebuilding and redeploying the entire Worker. The compiled registry was also excluded from git (`.gitignore`) since it was a build artifact.

**Decision:** Store registry data in Cloudflare KV (`secid_REGISTRY` namespace). Worker reads from KV at request time. `RegistryContext` provides per-request caching. `resolveFromKV()` fetches only the namespace(s) needed for each query.

**Rationale:** Registry updates become KV writes (no redeploy). Worker bundle drops from ~1.5 MB to ~1.2 MB (registry data removed from bundle). Per-request caching means repeated KV reads within one request are free. Partial fetching means a CVE lookup only loads the `advisory/mitre.org` namespace, not all 121.

**Rejected alternatives:**
- **Keep bundled registry** — Tight coupling between data and code, large bundle
- **External API/database** — Unnecessary complexity; KV is built into Workers and globally replicated

---

## ADR-006: KV registry upload via GitHub Actions

**Date:** 2025-03-05
**Status:** Accepted
**Decision method:** AI proposal, human approved

**Goal:** Automate registry data uploads when the spec repo changes.

**Context:** With KV-backed registry (ADR-005), need a way to push updated registry data. The SecID spec repo is the source of truth for registry JSON files.

**Decision:** GitHub Actions workflow (`registry-kv-upload.yml`) triggers on `repository_dispatch` from the spec repo or manual `workflow_dispatch`. Checks out both repos, runs tests, uploads to KV, then deploys the Worker.

**Rationale:** Fully automated pipeline from registry change to production. Tests run before upload. Manual trigger available for ad-hoc updates.

**Rejected alternatives:**
- **Manual wrangler CLI uploads** — Error-prone, no test gate
- **Webhook to Worker** — Worker would need write access to its own KV and a way to fetch/build registry data at runtime

---

## ADR-007: Observability via KV error logging

**Date:** 2025-03-05
**Status:** Accepted
**Decision method:** Collaborative — informed by operational philosophy of always-on, zero-config observability

**Goal:** Record errors with enough context to debug without external logging infrastructure.

**Context:** Cloudflare Workers have limited built-in observability. `console.log` output is ephemeral. Need persistent error records without adding external services (Sentry, Datadog, etc.).

**Decision:** Errors are recorded to `secid_OBSERVABILITY` KV namespace with UUIDv7 keys. Each entry captures error message, stack trace, request metadata, and parsed query state. Falls back to `console.log` if KV is unavailable.

**Rationale:** KV is already available (no new dependencies). UUIDv7 keys are time-sortable for browsing. Zero external services to configure or pay for. The fallback ensures errors are never silently lost.

**Rejected alternatives:**
- **External logging service** — Additional cost, config, and external dependency
- **Workers Analytics Engine** — Limited query capability, no stack traces

---

## ADR-008: Playwright E2E tests against live production site

**Date:** 2025-03-05
**Status:** Accepted
**Decision method:** Collaborative

**Goal:** Verify the full user experience — website, resolver, explorer, downloads, external links.

**Context:** Vitest with `@cloudflare/vitest-pool-workers` tests the Worker logic in isolation. But the website's interactive resolver (form, example buttons, explorer drill-down) and integration with the live API had no test coverage.

**Decision:** Playwright tests in `e2e/` run against the live production site (`SITE_URL` from `.env`). Chromium only, 30s timeout, 1 retry. Separate from vitest (which is scoped to `test/`).

**Rationale:** Testing the live site validates the full stack: static site + Worker API + KV registry. No need to replicate the Cloudflare environment locally. The site is public with no auth, making live testing straightforward.

**Rejected alternatives:**
- **Vitest + jsdom** — Can't test real browser interactions, API calls, downloads
- **Local dev server testing** — `wrangler dev` doesn't fully replicate Workers Assets + KV bindings

---

## ADR-009: Accept MCP SDK bundle size, skip zod locale stripping

**Date:** 2025-03-05
**Status:** Accepted
**Decision method:** Collaborative — informed by Cloudflare Workers pricing model analysis

**Goal:** Determine whether to optimize the Worker bundle size by stripping unused zod locale files.

**Context:** The Worker bundle is 1.2 MB uncompressed / 218 KB gzipped. Analysis showed 88% comes from the MCP SDK's dependency chain: zod (657 KB, including 269 KB of 40 unused locale translations), ajv (230 KB), zod-to-json-schema (44 KB). The actual application code is 1.5 KB. A wrangler alias shim could replace the locale barrel with English-only, saving ~263 KB.

**Decision:** Don't strip the locales. Accept the current bundle size.

**Rationale:** Cloudflare Workers billing is based on CPU milliseconds and request count — bundle size has zero cost impact. The bundle is 2% of the 10 MB Worker size limit. The alias shim (`wrangler.toml [alias]` pointing at an internal zod path) would break silently if zod restructures its internals in a minor update, adding maintenance burden for zero financial benefit. If the bundle approaches the size limit in the future, this optimization is available.

**Rejected alternatives:**
- **Zod locale alias shim** — Fragile (depends on zod internal paths), saves ~263 KB but costs $0
- **Fork/replace MCP SDK** — Would lose protocol compliance and automatic spec tracking
- **Bundle size CI check** — Useful in principle but premature; we're at 2% of the limit

---

## ADR-010: CI/CD authentication strategy

**Date:** 2025-03-05
**Status:** Accepted
**Decision method:** Collaborative — informed by Cloudflare docs, GitHub best practices, and organizational context

**Goal:** Securely authenticate two CI/CD flows: (1) deploying the Worker and uploading registry data to Cloudflare KV, and (2) triggering SecID-Service builds from the SecID spec repo.

**Context:** Two secrets are needed. The Cloudflare API token grants access to deploy Workers and write KV data. The cross-repo trigger lets the spec repo tell the service repo "registry data changed, rebuild." Both repos are under the `CloudSecurityAlliance` GitHub org.

**Decision:**

**Cloudflare:** Create a scoped API token (not a global API key) via the Cloudflare dashboard using the "Edit Cloudflare Workers" template. Scope to the SecID-Service account only, with permissions: Workers KV Storage (Edit), Workers Scripts (Edit), Workers Routes (Edit). Store as `CLOUDFLARE_API_TOKEN` in SecID-Service repo secrets.

**Cross-repo trigger:** Start with a fine-grained GitHub PAT scoped to `CloudSecurityAlliance/SecID-Service` with Contents (Read and Write) permission. Store as `SERVICE_REPO_TOKEN` in SecID repo secrets. Migrate to a GitHub App before v1.0.

**Rationale:**

*Cloudflare:* Scoped API tokens follow least-privilege — the token can only manage Workers and KV for this account, not DNS, firewall rules, or other Cloudflare services. The account ID isn't sensitive (already in `wrangler.toml`).

*Cross-repo:* A GitHub App is the org-level best practice (own identity, short-lived tokens, not tied to a person, higher rate limits, org-auditable). But a fine-grained PAT is adequate to start and can be swapped to a GitHub App later without changing workflow files — just replace the secret. The migration is a TODO for pre-v1.0.

**Rejected alternatives:**
- **Cloudflare global API key** — Grants access to everything on the account; violates least-privilege
- **Classic GitHub PAT with `repo` scope** — Far too broad; grants access to all repos the user can see
- **GitHub App immediately** — More setup (create app, install on both repos, generate keys) for a flow that isn't running yet. Fine-grained PAT unblocks the pipeline now; migrate later when it matters

---

## ADR-011: Accept regex runtime risk with registry-layer controls

**Date:** 2026-03-06  
**Status:** Accepted  
**Decision method:** Collaborative

**Goal:** Define how SecID-Service handles ReDoS risk from registry-provided regex patterns.

**Context:** Resolver paths compile and execute registry `patterns` against user input. A pathological pattern could trigger catastrophic backtracking and increase CPU time per request.

**Decision:** Keep runtime regex matching, and control risk at the registry authoring/review layer. Require regex safety checks in SecID registry workflow and PR review, with rollback as the operational response if a bad pattern escapes review.

**Rationale:**
- SecID depends on source-specific identifier patterns; removing regex matching would materially reduce coverage and accuracy.
- Registry controls are centralized and auditable.
- Cloudflare Worker runtime limits and existing observability provide containment and detection, but are not primary prevention.

**Controls:**
- Anchored patterns and anti-backtracking guidance in SecID docs.
- Required regex safety review notes in registry PRs.
- Cross-runtime compatibility checks for patterns used by clients and service.

**Residual risk:** Non-zero. If production telemetry indicates regex abuse/regression, rollback the offending registry change and re-review before re-deploy.
