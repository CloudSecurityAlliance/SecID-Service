# WAITING-FOR-001: Registry content propagation to live KV

**Status:** Open
**Date identified:** 2026-04-30
**Date resolved:** —
**Type:** Decision

## Waiting for

KV deploy chain to be repaired so that registry changes accumulated in `main` since 2026-04-30 can reach the live resolver. Specifically:

- 14 new CSAF advisory namespaces (provider entries created during research push)
- 5 updated existing CSAF entries
- Format metadata fields (`parsability`, `schema`, `parsing_instructions`, `auth`) added across all URL objects in the registry

## Why waiting

The technical fix path is documented in [FRICTION-001](../FRICTION/FRICTION-001.md). Until that's resolved, attempting to push the new content into KV via partial workarounds (e.g., manual `wrangler kv key put` for individual entries) would create a more confusing state than waiting:

- We'd have a hand-edited subset of KV inconsistent with what the deploy chain produces
- The next successful auto-sync would either overwrite the manual edits or (worse, in `--sync` mode with `--delete-orphans`) start deleting keys we hand-edited
- Auditing what's actually live would require diffing the JSON files against KV manually, which is exactly the work the auto-deploy was built to avoid

The right call is to fix the deploy chain end-to-end and let one clean sync land everything that's queued up.

## Trigger

Specific, observable: `gh run list --workflow=registry-kv-upload.yml --limit 1 -R CloudSecurityAlliance/SecID-Service` shows `success` for a recent run, AND a spot check on a known-changed entry returns the updated data:

```bash
curl 'https://secid.cloudsecurityalliance.org/api/v1/resolve?secid=secid:advisory/<one-of-the-14-new-CSAF-providers>'
```

returns a non-404 result.

## Next action

When triggered:

1. Verify the 14 new CSAF entries resolve correctly via the live resolver
2. Verify the 5 updated CSAF entries return their updated data (not stale cached values)
3. Verify format metadata fields (`parsability`, `schema`, `parsing_instructions`, `auth`) appear in resolver responses
4. Update [project_format_metadata.md](file:///Users/kurt/.claude/projects/-Volumes-MacMiniData-Users-kurt-GitHub-CloudSecurityAlliance-SecID/memory/project_format_metadata.md) memory entry with "deployed to production" status
5. Mark this entry **Resolved**

## Related

- [FRICTION-001](../FRICTION/FRICTION-001.md) — the underlying deploy chain breakage
- [OPERATIONAL-RESOURCES.md](../OPERATIONAL-RESOURCES.md) — deploy chain as an operational resource
