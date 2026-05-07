# FRICTION-001: KV deploy chain blocked

**Status:** Open
**Date identified:** 2026-04-30
**Date resolved:** —
**Type:** Process overhead

## Description

The auto-deploy chain that pushes registry JSON changes from the SecID spec repo to the live KV-backed resolver has been broken since 2026-04-30. Two independent failures stack:

1. **Auto-trigger fails.** Push to `main` in the SecID repo touching `registry/**/*.json` runs `update-registry.yml`, which uses `peter-evans/repository-dispatch@v3` with the `SECID_TO_SERVICE_DISPATCH` PAT to send a `repository_dispatch` event to SecID-Service. The dispatch step now returns *unauthorized* — the token has either expired, been revoked, or lost the required scope.
2. **Manual `workflow_dispatch` of Stage 2 fails.** Even bypassing the dispatch token by triggering `registry-kv-upload.yml` directly, the workflow fails on the `npx vitest run` step due to one or more `cve-schema` test failures introduced by registry content changes that the test harness no longer accepts.

The combined effect: registry content changes accumulate in `main` but cannot reach `secid_REGISTRY` KV. Currently stalled work includes 14 new CSAF advisory entries, 5 updated CSAF entries, and the format metadata fields (`parsability`, `schema`, `parsing_instructions`, `auth`) added across all URL objects.

## Attention tax

**Significant.** Every registry-touching commit is shadowed by "this isn't reaching production" — degrades the value of registry contributions, encourages batching changes (which itself adds friction), and erodes confidence in the auto-deploy pattern. Feels worse on days where multiple namespaces are added because the gap widens visibly.

## Reproduction

### Stage 1 (token failure)

1. Push a change to `registry/<type>/<tld>/<file>.json` in [CloudSecurityAlliance/SecID](https://github.com/CloudSecurityAlliance/SecID) `main`
2. Observe `Notify registry update` workflow run at https://github.com/CloudSecurityAlliance/SecID/actions
3. Step "Trigger SecID-Service registry upload" fails with HTTP 401/403 from GitHub's repository-dispatch API

### Stage 2 (test failure)

1. Trigger `Upload registry to KV` manually: `gh workflow run "Upload registry to KV" -R CloudSecurityAlliance/SecID-Service`
2. Observe run logs at https://github.com/CloudSecurityAlliance/SecID-Service/actions
3. `Run tests` step (`npx vitest run`) fails on `cve-schema`-related test cases

## Workaround

**No working production path for KV updates as of 2026-05-07.**

Local dry-run audit (no mutations, requires working `CLOUDFLARE_API_TOKEN`):

```bash
cd /path/to/SecID-Service
CLOUDFLARE_API_TOKEN=<token> npx tsx scripts/upload-registry-kv.ts --sync --dry-run /path/to/SecID
```

This shows what would be uploaded without doing it. Useful to confirm the registry build is sound while the test gate is broken.

## Root cause hypotheses

**Stage 1 (more straightforward):**
- Fine-grained PAT `SECID_TO_SERVICE_DISPATCH` may have hit its 1-year max lifetime
- Token may have lost the `metadata: read` + `contents: read` permission via permission audit
- SecID-Service repository-dispatch permission may have been changed to require higher scopes

**Stage 2 (needs investigation):**
- A registry contribution introduced a JSON shape that violates a Vitest schema fixture's expectations
- The `cve-schema` test suite likely tests that a specific CVE schema file (registry entry?) parses to a specific shape, and the underlying file changed
- Less likely: a Vitest version mismatch from a dependency bump

## Resolution plan

1. Inspect `gh run view --log-failed` for the most recent failed run to identify the exact assertion in `cve-schema`
2. Either fix the registry data, fix the test expectation, or fix the schema (whichever is genuinely wrong)
3. Get a successful local `npx vitest run`
4. Regenerate `SECID_TO_SERVICE_DISPATCH` with appropriate scope; update GitHub repository secret
5. Trigger end-to-end test: `gh workflow run "Notify registry update" -R CloudSecurityAlliance/SecID`
6. Confirm KV is populated and Worker is redeployed
7. Move all stalled registry content (14 new CSAF entries + format metadata) into production
8. Mark this friction Resolved; add a runbook to `OPERATIONAL-RESOURCES.md` for token rotation cadence

## Related

- [WAITING-FOR-001](../WAITING-FOR/WAITING-FOR-001.md) — registry content waiting on this resolution
- [OPERATIONAL-RESOURCES.md](../OPERATIONAL-RESOURCES.md) — "GitHub Actions — Deploy chain (cross-repo)" section
