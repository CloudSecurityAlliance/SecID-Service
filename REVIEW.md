@AGENTS.md

# Code Review Rules — CloudSecurityAlliance/SecID-Service

This file provides review instructions for automated and agent reviewers (Claude Code Review, GitHub Copilot Code Review, and human/agent reviewers). OpenAI Codex (`codex review` / `codex exec`) reads the matching [`## Code Review Rules`](AGENTS.md#code-review-rules) section in [`AGENTS.md`](AGENTS.md).

Because **every merge to `main` runs `registry-kv-upload.yml`, syncs Cloudflare KV (`secid_REGISTRY`), and deploys the production Cloudflare Worker** at `secid.cloudsecurityalliance.org`, every pull request must be checked against the rules below.

## 1. Authority, Provenance, and CI/Deploy Guardrails

- **Agent attribution:** Agent-authored commits must end with the trailer `AI-Agent: <Name>`, and agent-authored PR descriptions and review comments must start with `*Agent: <Name> (SecID governing agent)*` (or the contributing agent's role).
- **No self-weakening of gates:** Any PR that modifies `.github/workflows/ci.yml`, `.github/workflows/registry-kv-upload.yml`, `wrangler.toml`, `AGENTS.md`, or `REVIEW.md` must be scrutinized to ensure it does not weaken pre-deploy unit tests (`npm test`), post-deploy Playwright verification (`npm run test:e2e`), or KV sync safety guards without an independent cross-vendor review recorded on the PR.
- **Secrets and configuration:** Never commit secrets or tokens. Verify that account IDs, KV namespace IDs (`secid_REGISTRY`, `secid_OBSERVABILITY`, `secid_FEEDBACK`), and Analytics Engine bindings (`secid_DEMAND`) in `wrangler.toml` are not accidentally altered or pointed at test resources.

## 2. MCP Output Sanitization and Untrusted Input Handling

- **Recursive MCP output sanitization (`src/sanitize.ts`):** Every MCP tool (`resolve`, `lookup`, `describe` in `src/mcp.ts`) that returns registry-derived data must pass its output through `sanitizeResult()` / `sanitizeEnvelope()`. Verify that changes to response shapes or `src/sanitize.ts`:
  - Recursively traverse nested objects and arrays (`sanitizeDict`) so untrusted prose fields (`description`, `notes`, `note`, `purpose`, `reason`, `guidance`, `examples`, `disclaimer`, `summary`, `title`) at any depth are relocated into `_untrusted_prose` with the `_prose_warning` prompt-injection notice.
  - Recursively cap strings, arrays, and nested dictionaries via `capValue()` (`MAX_STRING_LEN`) even on keys that are not relocated.
- **`submit_feedback` isolation (`src/feedback.ts`):** Caller-supplied text (`secid`, `message`, `suggested_urls`) must always remain inside the `untrusted` envelope (`schema_version: 2`) with the `handling` warning intact, and must never be interpolated into executable contexts or log strings unsanitized.

## 3. `/mcp` HTTP Method Gate Parity (ADR-015)

- **Explicit method handling (`src/method-gate.ts`):** The `/mcp` endpoint is stateless POST-only. Any change to `src/method-gate.ts` or `/mcp` routing in `src/index.ts` must preserve:
  - `405 Method Not Allowed` (with `Allow: POST, OPTIONS`) for MCP-client `GET`/`HEAD` and other registered non-POST methods.
  - `302` redirect to `/#mcp-setup` **only** for positively identified browsers (`Accept: text/html` + browser `User-Agent`). Never redirect an MCP SDK client or hold an SSE stream open (either causes SDK clients to reconnect in a tight loop).
  - `501 Not Implemented` for unregistered HTTP methods.
- **Cross-repo parity:** `src/method-gate.ts` shares its contract with `CSA-MCP-Core`'s `src/mcp/method-gate.ts`. Any change requires updating both `test/method-gate.test.ts` and `e2e/mcp.spec.ts` and flagging the corresponding `CSA-MCP-Core` update.

## 4. Abuse-Resistance and Operational Limits

Verify that changes to `src/index.ts`, `src/api.ts`, `src/mcp.ts`, `src/feedback.ts`, or `src/write-budget.ts` do not bypass or weaken operational limits:
- **`secid` query length:** ≤ 1024 characters across both REST (`/api/v1/resolve`) and MCP (`resolve`, `lookup`, `describe`, `submit_feedback`).
- **MCP HTTP request body:** ≤ 64 KiB counted on actual received bytes (including chunked transfers without `Content-Length`), returning `413` when exceeded.
- **MCP JSON-RPC batching:** ≤ 10 messages per batch, and batches containing `submit_feedback` must be rejected with `400`.
- **`submit_feedback` rate and size limits:** `message` 1–4000 chars, `suggested_urls` ≤ 10 entries of ≤ 2048 chars each, and write budget capped at 20 writes per minute per isolate (`src/write-budget.ts`).

## 5. KV Sync Safety and Resolver Semantics

- **KV upload safety (`scripts/upload-registry-kv.ts`):** Preserve the 50-orphan deletion safety threshold in `--sync` mode (unless `--force` is explicitly passed) and the 25 MiB per-key KV value size check.
- **Stateless runtime (`src/kv-registry.ts`, `src/kv-resolve.ts`):** Production resolution reads exclusively from Cloudflare KV (`secid_REGISTRY`). `src/registry.ts` is a gitignored build snapshot used only to seed tests (`npm run build:registry`); runtime code must never import `src/registry.ts` directly.
- **Resolver fidelity (`src/parser.ts`, `src/resolver.ts`, `src/type-registry.ts`):**
  - `src/type-registry.ts` (`TYPE_REGISTRY`) is the single source of truth for types and subtypes. If modified, flag the lockstep update required in `CloudSecurityAlliance/SecID` (`scripts/validate-type-list.py`, `scripts/validate-subtypes.py`).
  - Preserve the four response outcomes (`found`, `corrected`, `related`, `not_found`), shortest-to-longest namespace matching, exact subpath preservation (no lossy normalization), and `SecID-Server-API` parity.

## 6. Testing and Post-Deploy Verification

- **Unit/integration coverage (`test/`):** Every parser, resolver, sanitization, KV, or MCP change must include Vitest regression tests (`npm test`).
- **Registry test guards during release trains:** When a registry source in `CloudSecurityAlliance/SecID` transitions from unversioned to `version_required: true` (or changes version lists), `test/resolver.test.ts` assertions in this repository must be updated or made version-agnostic **before** the `SecID` registry PR merges, so the triggered `Upload registry to KV` workflow does not fail in its pre-deploy test step.
- **Playwright E2E gate (`e2e/`):** User-facing website (`website/`) or `/mcp` routing changes must be covered in `e2e/`. Any e2e test that fetches external third-party URLs must be tagged `@third-party` so it is excluded from the production post-deploy gate (`--grep-invert @third-party`).
