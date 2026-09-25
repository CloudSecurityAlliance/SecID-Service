# Demand signal: namespace misses

When someone asks the resolver for `secid:entity/some-new-vendor.io`, the type is valid but the namespace is not in the registry. A real domain we don't cover is a request for coverage. Counted over time, these requests become a ranked list of what to add next. This document covers how we record them, what we store, and how to read them.

## Capture and processing are separate

| Stage | Where | What happens |
|---|---|---|
| **Capture** | The Worker, on every request (`src/demand.ts`) | One data point goes to Workers Analytics Engine. There is no read, no key, and no aggregation. The call is non-blocking and best-effort: it never throws and never delays the response, and when the binding is absent it does nothing. |
| **Processing** | Offline, in batches (`scripts/export-misses.ts`) | A read-only SQL query covers a time window, drops namespaces that are registered at export time, and prints a digest sorted by count. People or agents triage that digest. |

Capture used to be a KV read-modify-write on `miss:<type>/<namespace>`. That was the wrong store for an event log:

- every miss cost a paid KV write;
- concurrent requests lost counts, because KV has no atomic increment;
- an anonymous caller chose the keys we paid to write.

Analytics Engine is built for append-only events, and it prices every data point the same (see Pricing below).

## What is recorded, and what never is

A miss is recorded only when all of these hold:

- The type is one of the ten SecID types. The parser checks this.
- The namespace is not registered for that type. A case variant of a registered namespace also counts as registered.
- The namespace is a syntactically valid DNS name: RFC 1035 labels, at most 253 characters, and IDNs in `xn--` form. Its last label must be a TLD that IANA has delegated. `src/tlds.ts` holds that list; regenerate it with `npx tsx scripts/update-tlds.ts`.
- The lowercased namespace is at most 96 bytes, which is Analytics Engine's index limit.

Typos and invented domains, such as `foo.notarealtld`, `constructor` or 300 characters of junk, are not our problem, so they are never recorded. The filter does not bound volume: `random-label.com` is valid and gets through. That is deliberate, because a real domain we don't have is exactly what we want to hear about. The batch step separates signal from noise by count and by the number of distinct days.

Each data point:

| Column | Value |
|---|---|
| `index1` | namespace (lowercased) |
| `blob1` | type |
| `blob2` | namespace (lowercased) |
| `blob3` | channel: `rest` or `mcp` |
| `blob4` | status that triggered it (today always `not_found`) |
| `double1` | `1` |

**No free text from the caller is stored:** no raw query, subpath, version, qualifiers, IP or user agent. Every stored value has been validated or comes from a fixed set. There are two reasons:

1. A downstream triage agent never reads attacker-authored prose from this dataset.
2. The dataset holds nothing personal.

The `submit_feedback` tool, which does carry free text, stays in the `secid_FEEDBACK` KV namespace. Those records keep caller text under an `untrusted` envelope.

## Retention: run the batch job more often than every three months

Analytics Engine keeps data for **three months**, and anything older is gone. The export is the only durable record, so the batch job must run well inside that window. Run it weekly with the default `--days 7`, or at the very least monthly, and keep each digest, for example by committing it or attaching it to an issue. `--days` is capped at 90.

## Running the export

```bash
CLOUDFLARE_ACCOUNT_ID=f3898058ae0b4c20c692bbfa5b9b44b0 \
CLOUDFLARE_API_TOKEN=<read-only analytics token> \
  npx tsx scripts/export-misses.ts /path/to/SecID --days 7 > misses.json
```

- The SecID checkout is used only to drop namespaces that are already registered, so the digest shows gaps.
- Each entry has `count`, `distinct_days`, `first_seen`, `last_seen`, per-`channels` counts, and `registered_as`. The last field lists other types the namespace is registered under, which hints at a cross-type gap rather than a missing organisation.
- Counts use `SUM(_sample_interval)`, because Analytics Engine may sample indexes that receive heavy traffic.
- The script performs one SQL API read and never writes.

## What Kurt must configure

1. **Deploy.** The `[[analytics_engine_datasets]]` binding (`secid_DEMAND` → dataset `secid_demand_misses`) is in `wrangler.toml`. Cloudflare creates the dataset on its first write, so there is nothing to create beforehand. After the first deploy, confirm that writes arrive: run the export, or run `SHOW TABLES` through the SQL API.
2. **A read-only API token for the export.** In the dashboard, go to My Profile, then API Tokens, then Create Custom Token. Grant **Account → Account Analytics → Read** and scope it to the SecID account. It needs nothing else. Keep it separate from `SECID_SERVICE_DEPLOY`.
3. **Plan headroom.** Workers Paid includes 10 million data points written and 1 million read queries per month; beyond that, $0.25 per additional million points. Workers Free includes 100,000 points and 10,000 queries per day. One export is one read query.
4. **Old KV keys.** Existing `miss:*` keys in `secid_FEEDBACK` are left in place; nothing writes or reads them any more. Deleting them is a separate follow-up: export them first if their history matters.

## Verified facts (Cloudflare docs, checked 2026-09-25)

| Fact | Source |
|---|---|
| Binding: `[[analytics_engine_datasets]]` with `binding` and `dataset` (the dataset defaults to the binding name) | [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/#analytics-engine-datasets), [Get started](https://developers.cloudflare.com/analytics/analytics-engine/get-started/) |
| Per `writeDataPoint`: up to 20 blobs, 20 doubles and 1 index; blobs total at most 16 KB per data point; an index at most 96 bytes | [Limits](https://developers.cloudflare.com/analytics/analytics-engine/limits/) |
| At most 250 data points per Worker invocation (client HTTP request) | [Limits](https://developers.cloudflare.com/analytics/analytics-engine/limits/) |
| Retention: three months | [Limits → Data retention](https://developers.cloudflare.com/analytics/analytics-engine/limits/#data-retention) |
| Supplying more than one index means the data point is not recorded | [Get started](https://developers.cloudflare.com/analytics/analytics-engine/get-started/) |
| `writeDataPoint` is non-blocking and should not be awaited | [Workers prompting guide](https://developers.cloudflare.com/workers/get-started/prompting/) |
| Pricing: Paid includes 10M points and 1M queries per month (+$0.25/M points, +$1.00/M queries); Free includes 100k points and 10k queries per day | [Pricing](https://developers.cloudflare.com/analytics/analytics-engine/pricing/) |
| SQL API: `POST https://api.cloudflare.com/client/v4/accounts/<account_id>/analytics_engine/sql` with a Bearer token; the token permission is Account → Account Analytics → Read | [SQL API](https://developers.cloudflare.com/analytics/analytics-engine/sql-api/) |
| Sampling is keyed on the index; use `SUM(_sample_interval)` for counts | [SQL API → Sampling](https://developers.cloudflare.com/analytics/analytics-engine/sql-api/#sampling) |
| Datasets are created implicitly by writes | [Previews → Resources](https://developers.cloudflare.com/workers/previews/resources/) |
