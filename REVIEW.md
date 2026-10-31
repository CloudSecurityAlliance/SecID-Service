@AGENTS.md

# Code Review Rules — CloudSecurityAlliance/SecID-Service

Review instructions for Claude Code Review, GitHub Copilot Code Review, and human/agent reviewers. OpenAI Codex (`codex review` / `codex exec`) reads the matching [`## Code Review Rules`](AGENTS.md#code-review-rules) section in [`AGENTS.md`](AGENTS.md).

Because **every merge to `main` runs `registry-kv-upload.yml`, syncs Cloudflare KV (`secid_REGISTRY`), and deploys the production Cloudflare Worker** at `secid.cloudsecurityalliance.org`, check every PR against these rules:

## 1. Authority, Provenance, and CI/Deploy Guardrails

- **Agent attribution:** Agent-authored commits must end with `AI-Agent: <Name>`, and agent PR descriptions/comments must start with `*Agent: <Name> (SecID governing agent)*` (or the contributing agent's role).
- **Governance and gate changes:** Every change to `.github/workflows/ci.yml`, `.github/workflows/registry-kv-upload.yml`, `wrangler.toml`, `AGENTS.md`, or `REVIEW.md` unconditionally requires an independent cross-vendor review and decision record, and must never weaken pre-deploy unit tests (`npm test`), post-deploy Playwright verification (`npm run test:e2e`), or KV sync safety guards. Widening agent authority requires Kurt's approval first.
- **Secrets and configuration:** Never commit secrets or tokens. Verify that account IDs, KV namespace IDs (`secid_REGISTRY`, `secid_OBSERVABILITY`, `secid_FEEDBACK`), and Analytics Engine bindings (`secid_DEMAND`) in `wrangler.toml` are not altered or pointed at test resources.

## 2. MCP Output Sanitization and Untrusted Input Handling

- **Recursive MCP output sanitization (`src/sanitize.ts`):** Every MCP tool (`resolve`, `lookup`, `describe` in `src/mcp.ts`) returning registry-derived data must pass its output through `sanitizeResponseForMcp()`. Verify that changes to response shapes or `src/sanitize.ts`:
  - Recursively traverse nested objects and arrays (`sanitizeDict()` / `sanitizeValue()`) so `UNTRUSTED_TEXT_KEYS` (`description`, `notes`, `note`, `official_name`, `common_name`, `auth`, `contacts`, `contact`, `scope`, `policy`, `disclosure_policy`, `version_disambiguation`, `unversioned_behavior`, `parsing_instructions`) at any depth are relocated into `registry_text_untrusted` with `registry_text_untrusted._warning`.
  - Strip C0/C1 control, zero-width, and bidi-override characters (`CONTROL_RE`) and recursively cap strings, arrays, and nested dicts via `capString()` / `capValue()` (`MAX_FIELD_CHARS = 4000`, `MAX_ARRAY_ITEMS = 64`).
- **`submit_feedback` isolation (`src/feedback.ts`):** Caller-supplied text (`secid`, `message`, `suggested_urls`) must remain inside the `untrusted` envelope (`schema_version: 2`) with the `handling` warning intact.

## 3. `/mcp` HTTP Method Gate Parity (ADR-015)

- **Explicit method handling (`src/method-gate.ts`):** The `/mcp` endpoint is stateless POST-only (`OPTIONS` passes through to CORS middleware and returns `204`). Any change to `src/method-gate.ts` or `/mcp` routing in `src/index.ts` must preserve:
  - `405 Method Not Allowed` (with `Allow: POST, OPTIONS`) for registered non-POST, non-OPTIONS methods (`GET`, `HEAD`, `PUT`, `PATCH`, `DELETE`, `QUERY`, `TRACE`, `CONNECT`) from non-browsers.
  - `302` redirect to `/#mcp-setup` **only** for `GET`/`HEAD` requests passing `isBrowserNavigation()` (which rejects MCP-client signals `Accept: text/event-stream`, `Mcp-Protocol-Version`, and `Mcp-Session-Id` first, then accepts `Sec-Fetch-Mode: navigate` **or** `Accept: text/html`). Never redirect an MCP SDK client or hold an SSE stream open.
  - `501 Not Implemented` for unregistered HTTP methods.
- **Cross-repo parity:** `src/method-gate.ts` shares its contract with `CSA-MCP-Core`'s `src/mcp/method-gate.ts`. Any change requires updating both `test/method-gate.test.ts` and `e2e/mcp.spec.ts` and flagging the corresponding `CSA-MCP-Core` update.

## 4. Abuse-Resistance and Operational Limits

Preserve explicit limits across `src/index.ts`, `src/api.ts`, `src/mcp.ts`, `src/feedback.ts`, and `src/write-budget.ts`:
- **`secid` query length:** ≤ 1024 characters across REST (`/api/v1/resolve`) and MCP (`resolve`, `lookup`, `describe`, `submit_feedback`).
- **MCP HTTP request body:** ≤ 64 KiB counted on actual received bytes (including chunked transfers without `Content-Length`), returning `413` when exceeded.
- **MCP JSON-RPC batching:** ≤ 10 messages per batch, and batches containing `submit_feedback` must be rejected with `400`.
- **`submit_feedback` limits:** `message` 1–4000 chars, `suggested_urls` ≤ 10 entries of ≤ 2048 chars each, capped at 20 writes/min/isolate (`src/write-budget.ts`).

## 5. KV Sync Safety and Resolver Semantics

- **KV upload safety (`scripts/upload-registry-kv.ts`):** Preserve the 50-orphan deletion safety threshold in `--sync` mode (unless `--force` is passed) and the 25 MiB per-key KV value size check.
- **Stateless runtime (`src/kv-registry.ts`, `src/kv-resolve.ts`):** Production resolution reads exclusively from Cloudflare KV (`secid_REGISTRY`), never from the gitignored test snapshot `src/registry.ts`.
- **Resolver fidelity (`src/parser.ts`, `src/resolver.ts`, `src/type-registry.ts`):** Keep `src/type-registry.ts` (`TYPE_REGISTRY`) in lockstep with `CloudSecurityAlliance/SecID` (`scripts/validate-type-list.py`, `scripts/validate-subtypes.py`) and `SecID-Server-API`.

## 6. Testing and Post-Deploy Verification

- **Unit/integration coverage (`test/`):** Require Vitest regression tests (`npm test`) for parser, resolver, sanitization, KV, or MCP changes.
- **Release-train test guards:** When a source in `CloudSecurityAlliance/SecID` transitions to `version_required: true` or changes version lists, update assertions in `test/resolver.test.ts` / `test/website.spec.ts` here **first** before merging the `SecID` registry PR.
- **Playwright E2E gate (`e2e/`):** Tag any e2e test that fetches external third-party URLs with `@third-party` so it is excluded from the production post-deploy gate (`--grep-invert @third-party`).
