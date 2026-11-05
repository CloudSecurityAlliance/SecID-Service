# Backup Resources

Index of how SecID-Service operational state is backed up. Pairs with [OPERATIONAL-RESOURCES.md](OPERATIONAL-RESOURCES.md) (what runs vs. how it survives).

---

## Registry data (`secid_REGISTRY` KV)

**What's being backed up.** The compiled registry data the Worker reads at request time. Note: the KV itself is *not* directly backed up — it's a cache, regenerable from authoritative sources.

- **Where it lives in production:** Cloudflare KV namespace `cfbc271787614516a39fa43d9ca4f95a` on account `f3898058ae0b4c20c692bbfa5b9b44b0`
- **Backup repo:** [CloudSecurityAlliance/SecID](https://github.com/CloudSecurityAlliance/SecID) — the authoritative source. KV is rebuilt from `registry/**/*.json` via `scripts/build-registry.ts`
- **Backup mechanism:** Git on GitHub (the SecID spec repo); GitHub itself is backed up via [`CSA-Backups-GitHub`](https://github.com/CloudSecurityAlliance-Backups/CSA-Backups-GitHub) for org-wide metadata
- **Cadence:** continuous (every commit to SecID main is a new "backup" point)
- **Last verified:** 2026-11-04 (continuous auto-sync via `registry-kv-upload.yml`; FRICTION-001 resolved 2026-09-25)
- **Recovery path:** With a working Cloudflare API token, run `npx tsx scripts/upload-registry-kv.ts --sync /path/to/SecID` from this repo. KV is fully reconstructed from JSON files in ~30 seconds
- **Owner:** Kurt Seifried
- **Notes:** Verified on every `registry-kv-upload.yml` deploy run

## Observability data (`secid_OBSERVABILITY` KV)

**What's being backed up.** Error and access log records.

- **Where it lives in production:** Cloudflare KV namespace `c5cbc52b9a724433b3043efdf31857f4`
- **Backup repo:** **none — not backed up by design**
- **Backup mechanism:** N/A
- **Cadence:** N/A
- **Last verified:** N/A
- **Recovery path:** Logs are ephemeral (30-day automatic KV `expirationTtl`); data loss is acceptable. New errors will be recorded as they occur
- **Owner:** Kurt Seifried
- **Notes:** Entries expire automatically after 30 days (`TTL_30_DAYS` in `src/observability.ts`). If observability data ever becomes load-bearing for compliance or incident analysis, this entry needs to change

## Feedback & demand signal (`secid_FEEDBACK` KV + `secid_DEMAND` Analytics Engine)

**What's being backed up.** Active MCP `submit_feedback` inbox items (`feedback:<uuidv7>` in `secid_FEEDBACK` KV) and passive namespace-miss telemetry (`secid_demand_misses` in Workers Analytics Engine).

- **Where it lives in production:** Cloudflare KV namespace `61642c6485674ef597cbff50fe9b9f18` (`secid_FEEDBACK`) and Workers Analytics Engine dataset `secid_demand_misses` (`secid_DEMAND`)
- **Backup repo:** **none — operational inbox and telemetry, not backed up directly**; actionable items are promoted into durable GitHub issues/PRs in [CloudSecurityAlliance/SecID](https://github.com/CloudSecurityAlliance/SecID) during triage
- **Backup mechanism:** Triage promotion to GitHub issues/commits (backed up via `CSA-Backups-GitHub`)
- **Cadence:** Triage-driven
- **Recovery path:** Open `feedback:<uuid>` records have no TTL and persist until triaged; once resolved via `resolveFeedback()`, they expire after 30 days (`RESOLVED_FEEDBACK_TTL_SECONDS`). Passive `secid_demand_misses` events are retained for 3 months by Analytics Engine
- **Owner:** Kurt Seifried

## DNS — `secid.cloudsecurityalliance.org`

**What's being backed up.** The DNS A/AAAA records and Worker route binding for the public hostname.

- **Where it lives in production:** Cloudflare DNS, zone `113bb8004441490558a7ce8b4b611cc1` (`cloudsecurityalliance.org`)
- **Backup repo:** [CloudSecurityAlliance-Backups/CSA-Backups-CloudFlare](https://github.com/CloudSecurityAlliance-Backups/CSA-Backups-CloudFlare) — captures DNS records and Cloudflare configs across CSA properties
- **Backup mechanism:** Periodic export from Cloudflare API (mechanism owned by `CSA-Backups-Management` project)
- **Cadence:** see CSA-Backups-CloudFlare README
- **Last verified:** check `CSA-Backups-CloudFlare/cloudsecurityalliance.org/` for the most recent export timestamp
- **Recovery path:** Restore DNS records from the BIND/JSON dump in `CSA-Backups-CloudFlare`. Worker route binding is also encoded in [`wrangler.toml`](wrangler.toml) here, so a fresh `wrangler deploy` re-establishes it
- **Owner:** Kurt Seifried (DNS owner); CSA-Backups-Management owns the backup pipeline

## Worker code + config

**What's being backed up.** The Worker source code, `wrangler.toml`, GitHub Actions workflows, and all deployment scripts.

- **Where it lives in production:** Compiled bundle on Cloudflare's edge (rebuilt on each `wrangler deploy`)
- **Backup repo:** [CloudSecurityAlliance/SecID-Service](https://github.com/CloudSecurityAlliance/SecID-Service) (this repo) — source of truth
- **Backup mechanism:** Git on GitHub, plus [`CSA-Backups-GitHub`](https://github.com/CloudSecurityAlliance-Backups/CSA-Backups-GitHub) for org metadata
- **Cadence:** continuous (every commit)
- **Last verified:** 2026-05-07 (this commit)
- **Recovery path:** `git clone` + `npm ci` + `npx wrangler deploy` (with `CLOUDFLARE_API_TOKEN` set)
- **Owner:** Kurt Seifried

## Cloudflare account secrets

**What's being backed up.** GitHub Actions secrets used by the deploy chain: `SECID_TO_SERVICE_DISPATCH` (PAT for cross-repo dispatch) and `SECID_SERVICE_DEPLOY` (Cloudflare API token).

- **Where it lives in production:** GitHub repository secrets (SecID and SecID-Service repos respectively)
- **Backup repo:** **none — secrets are not version-controlled by design**
- **Backup mechanism:** N/A; tokens are recreated/rotated as needed
- **Cadence:** N/A
- **Last verified:** 2026-04-30 (last known working state; one or both have lapsed since per FRICTION-001)
- **Recovery path:** Regenerate the GitHub PAT (fine-grained, scoped to SecID-Service only) and the Cloudflare API token (Workers KV Edit + Workers Scripts Edit on the SecID-Service Worker), then update the corresponding GitHub repository secret
- **Owner:** Kurt Seifried
- **Notes:** Token rotation policy not formalized. Each token's permissions and scope should be documented in a runbook; for now, see the GitHub Actions workflow definitions for which token does what
