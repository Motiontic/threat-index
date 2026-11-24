# MTI (Motiontic Threat Index): technical implementation plan

**Status:** draft v1, 22 November 2026
**Product spec:** the PRD on the design board (`prd.html`)
**Design:** the threat data system board (`index.html`)

This plan covers everything needed to build MTI (Motiontic Threat Index) end to end:

- pulling 55 public sources every 3 hours;
- storing them in Cloudflare (D1 + R2), with E2B doing the heavy work;
- serving search and entry pages;
- single-user accounts with Clerk;
- email alerts with Resend;
- testing, deployment, operations and open-sourcing.

Anything marked **(verify)** was not confirmed against current docs and must be checked before that piece is built.

---

## 0. The system in one page

```
            ┌──────────── Cloudflare (free plan) ─────────────────────────────────────┐
 55 sources │ Cron ─► ti-collector ─► Queue ti-jobs ─► ti-collector (consumer)         │
  (web) ◄───┼──── asks "anything new?", fetches only new items                        │
            │        │ small updates ─► D1 (hot set)      receipts ─► R2 raw/          │
            │        └─ big/rare file ─► E2B job ──┐                                   │
            │                                      ▼                                   │
            │                     ┌─ E2B sandbox (Node 22 + DuckDB) ─┐                │
            │                     │ download · parse · diff · Parquet │                │
            │                     └──► R2 lake/ (history) · inbox/ (hot rows)          │
            │ Queue ti-load ─► ti-loader ─► D1 (≤ 70k rows/day, budget meter)          │
            │ Queue ti-notify ─► ti-notify ─► Resend (alerts)                          │
            │ ti-api (Hono) ◄── ti-web (React Router SSR) ◄── users (Clerk sign-in)    │
            └──────────────────────────────────────────────────────────────────────────┘
```

| Layer           | Choice                                                                                       | Why                                                                                      |
| --------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Language        | TypeScript (strict), Node 22 locally and in E2B                                              | One language everywhere; parsers are shared by Workers and E2B                           |
| Repo            | pnpm workspaces monorepo                                                                     | Simple, fast, no extra build orchestrator needed                                         |
| Lint and format | Biome                                                                                        | One tool, zero config drift                                                              |
| Tests           | Vitest with `@cloudflare/vitest-pool-workers`; Playwright for the web app                    | Tests run against real local D1, R2 and Queues                                           |
| Edge compute    | Cloudflare Workers (free plan): `ti-collector`, `ti-loader`, `ti-notify`, `ti-api`, `ti-web` | $0; one deploy tool (Wrangler)                                                           |
| Scheduling      | Cron Triggers, 4 of the 5 free ones                                                          | Every 3 h, daily 14:45 UTC, nightly 02:30 UTC, weekly Mon 05:00 UTC                      |
| Queues          | `ti-jobs` (+ `ti-jobs-dlq`), `ti-load`, `ti-notify`                                          | Small pieces of work, retries, back-pressure                                             |
| Storage         | R2 (one bucket), D1 (6 databases), KV (settings)                                             | Receipts and history in R2, hot set in D1                                                |
| Heavy jobs      | E2B sandboxes from existing credits                                                          | No 10 ms CPU limit; DuckDB for big files and history                                     |
| API             | Hono on Workers                                                                              | Small, fast, first-class Workers support                                                 |
| Web             | React Router v7 (framework mode) on Workers, server-rendered                                 | Entry previews must be crawlable for search engines                                      |
| Auth            | Clerk, **single-user accounts, Organizations off**; email code, Google, GitHub               | Ready-made UI, no passwords, verified on the server                                      |
| Email           | Resend (free: 3,000/month, 100/day)                                                          | Plain HTTP API from Workers, batch sends, webhooks                                       |
| Schema          | SQL migrations applied with `wrangler d1 migrations`, typed with Drizzle                     | Plain SQL is reviewable, and Drizzle gives types                                         |
| CI/CD           | GitHub Actions: lint, typecheck, test, deploy with Wrangler                                  | Building, testing and deploying this repo's software, which GitHub's Actions terms allow |

---

## 1. Repository layout

```
threat-index/
├─ apps/
│  ├─ collector/      Cron + ti-jobs consumer: planner, 7 pull patterns, linker, watchdog
│  ├─ loader/         ti-load consumer: inbox/ rows → D1 inside the daily budget
│  ├─ notify/         ti-notify consumer: alert matching, digests, Resend
│  ├─ api/            Hono JSON API, Clerk auth, webhooks, internal job callbacks
│  └─ web/            React Router v7 SSR app (the platform UI)
├─ packages/
│  ├─ core/           types, ID normalisation, licence gates, budget meter, cursors
│  ├─ sources/        the 55-source registry (one typed entry per source)
│  ├─ patterns/       git · changelist · since · fingerprint · feed · page · heavy
│  ├─ parsers/        CVE JSON 5, OSV, CSAF 2.0, NVD 2.0, KEV, EPSS, STIX, RSS/Atom, CSV…
│  ├─ linker/         alias graph, hot-set rules, change log, company matching
│  └─ db/             SQL migrations per D1 database + Drizzle schema + query helpers
├─ e2b/
│  ├─ e2b.Dockerfile  sandbox template: Node 22, DuckDB, our jobs bundle
│  └─ jobs/           heavy jobs: first load, EPSS diff, nightly fold, compaction, deep query
├─ fixtures/          recorded sample responses per source (for tests)
├─ docs/              this plan, ADRs, adding-a-source guide
└─ .github/           CI, issue templates, Dependabot
```

---

## 2. Cloudflare resources

| Resource                  | Type          | Binding         | Used by                                                             |
| ------------------------- | ------------- | --------------- | ------------------------------------------------------------------- |
| `ti_control`              | D1            | `DB_CONTROL`    | all: sources, cursors, runs, jobs, budget                           |
| `ti_vulns`                | D1            | `DB_VULNS`      | collector, loader, api                                              |
| `ti_advisories`           | D1            | `DB_ADVISORIES` | collector, loader, api                                              |
| `ti_signals`              | D1            | `DB_SIGNALS`    | collector, loader, api, notify (change log)                         |
| `ti_world`                | D1            | `DB_WORLD`      | collector, loader, api (techniques, companies, breaches, incidents) |
| `ti_users`                | D1            | `DB_USERS`      | api, notify (accounts, watchlists, alerts)                          |
| `threat-index`            | R2 bucket     | `BUCKET`        | `raw/` `lake/` `inbox/` `docs/` `lookup/` `jobs/`                   |
| `TI_SETTINGS`             | KV            | `SETTINGS`      | source switches and display modes (read-heavy, rarely written)      |
| `ti-jobs` + `ti-jobs-dlq` | Queue         | `JOBS`          | collector (producer and consumer)                                   |
| `ti-load`                 | Queue         | `LOAD`          | api (job callbacks) → loader                                        |
| `ti-notify`               | Queue         | `NOTIFY`        | collector → notify                                                  |
| Cron triggers             | 4             | —               | collector                                                           |
| `send_email`              | Email Routing | `OPS_EMAIL`     | collector watchdog → verified ops address only                      |
| Service binding           | —             | `API`           | web → api                                                           |

**Cron schedules** (UTC):

- `0 */3 * * *`: every 3 hours. Runs fast sources, then instant alerts. The 03:00 run also sends daily digests, and weekly digests for users whose weekday matches.
- `45 14 * * *`: daily sources, after EPSS publishes (~13:30 UTC).
- `30 2 * * *`: nightly fold (raw/ → lake/) and the search-index rebuild.
- `0 5 * * 1`: weekly sources (ATT&CK, CWE, CAPEC, AIID, AIAAIC…) and lake compaction.

**Free-plan limits this design respects** (Cloudflare docs, 22 Nov 2026):

| Limit                                                                               | Rule in code                                                                                                    |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| 10 ms CPU per invocation                                                            | ≤ 40 records per queue message; anything over ~1 MB goes to E2B                                                 |
| 50 external subrequests per invocation                                              | batches of ≤ 40 URLs                                                                                            |
| D1 on Workers Paid: 50M rows written a month (about 1,600,000 a day); indexes count | budget meter stops the first load at 1,000,000 a day; natural-key `WITHOUT ROWID` tables; few secondary indexes |
| 500 MB per D1 database, 10 databases                                                | 6 databases, about 0.5 GB in total                                                                              |
| 10,000 queue operations per day                                                     | one message per batch, not per record (~2,000 operations a day)                                                 |
| 5 cron triggers                                                                     | 4 used                                                                                                          |
| R2: 10 GB, 1M Class A ops per month                                                 | bundle receipts per run, Parquet files, 180-day raw lifecycle                                                   |

---

## 3. Data model

All tables use the natural key as the primary key, and `WITHOUT ROWID` where possible, so a row costs one write. Secondary indexes exist only where a query needs them. The full SQL is in `packages/db/migrations/<database>/0001_init.sql`.

### `ti_control`

| Table     | Key         | Main columns                                                                                          |
| --------- | ----------- | ----------------------------------------------------------------------------------------------------- |
| `sources` | `id`        | name, pattern, cadence, licence_status, ingest (on/off), display (full/link/hidden), credit, homepage |
| `cursors` | `source_id` | kind (commit/timestamp/etag/version), value, etag, updated_at                                         |
| `runs`    | `id` (ULID) | source_id, started_at, finished_at, status, found, written, bytes, error                              |
| `jobs`    | `id` (ULID) | kind, source_id, status, sandbox_id, created_at, finished_at, manifest_key, error                     |
| `budget`  | `day`       | d1_writes, queue_ops, r2_class_a, emails_sent                                                         |

### `ti_vulns`

| Table   | Key                                          | Main columns                                                                                                                                                                                                                          |
| ------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vulns` | `key` (CVE ID, or the source ID when no CVE) | kind, title, summary (≤ 300 chars), published, modified, cvss, cvss_version, cvss_source, cwe (JSON), kev_added, kev_due, ransomware, exploit_public, epss, epss_pct, epss_date, epss_model, ai_related, hot, sources (JSON), doc_key |

### `ti_advisories`

| Table        | Key                     | Main columns                                                                              |
| ------------ | ----------------------- | ----------------------------------------------------------------------------------------- |
| `advisories` | (`source`, `source_id`) | vuln_key (indexed), status (active/withdrawn/rejected), published, modified, url, licence |

This table doubles as the alias map. Any ID (GHSA, RHSA, USN, JVNDB, EUVD…) resolves to its `vuln_key`.

### `ti_signals`

| Table     | Key                                   | Main columns                                                                                                                                 |
| --------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `signals` | (`vuln_key`, `kind`, `source`, `ref`) | kind (exploited_wild / public_exploit / detection / poc / ransomware), first_seen, evidence_date, url                                        |
| `changes` | `id` (ULID)                           | entity_key, kind (newly_exploited / public_exploit / epss_band / fix_released / cvss_change / breach_notice), old, new, at (indexed), source |

### `ti_world`

| Table             | Key                                       | Main columns                                                                                                                         |
| ----------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `techniques`      | `id` (T1190, AML.T0051, CWE-79, CAPEC-66) | framework, name, parent, summary                                                                                                     |
| `vuln_techniques` | (`vuln_key`, `technique_id`)              | origin (source / our rule)                                                                                                           |
| `companies`       | `key`                                     | name, cik, domain, ticker, sector, aliases (JSON)                                                                                    |
| `breach_notices`  | (`source`, `notice_id`)                   | company_key (indexed), raw_name, occurred_from/to, discovered, notified, count, count_unit, jurisdiction, data_types, url, event_key |
| `breach_events`   | `key`                                     | company_key, first_seen, dates, counts_by_unit (JSON), notice_count, confidence                                                      |
| `incidents`       | (`source`, `incident_id`)                 | kind (ai / cyber_op / cyber_event), title, date, entities, techniques, url, gated                                                    |

### `ti_users`

| Table            | Key                      | Main columns                                                                                                                                   |
| ---------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `users`          | `id` (Clerk user ID)     | email, name, created_at, plan ('free'), alert_frequency ('daily' default), alert_triggers (JSON), digest_weekday, email_suppressed, deleted_at |
| `watch`          | (`user_id`, `entry_key`) | created_at, alerts_on; index on entry_key                                                                                                      |
| `saved_searches` | (`user_id`, `id`)        | label, query, created_at                                                                                                                       |
| `alert_queue`    | (`user_id`, `change_id`) | created_at; pending items for digests                                                                                                          |
| `alerts_sent`    | (`user_id`, `change_id`) | sent_at; dedupe                                                                                                                                |
| `email_log`      | `day`                    | sent (daily cap counter)                                                                                                                       |
| `webhook_events` | `id` (svix-id)           | source (clerk/resend), received_at; idempotency                                                                                                |

### R2 layout

| Prefix                                          | What                                                     | Written by                | Kept                                                                                |
| ----------------------------------------------- | -------------------------------------------------------- | ------------------------- | ----------------------------------------------------------------------------------- |
| `raw/<source>/<yyyy>/<mm>/<dd>/<run>.ndjson.gz` | receipts, untouched                                      | collector, E2B            | 180 days + monthly copy (cleanup job; lifecycle rule if available on free (verify)) |
| `lake/<table>/<source>/<year>/part-*.parquet`   | full history                                             | E2B                       | forever, compacted weekly                                                           |
| `inbox/<job>/<n>.ndjson.gz` + `manifest.json`   | hot rows waiting for D1                                  | E2B                       | deleted after load                                                                  |
| `docs/vuln/<key>.json`                          | merged document per hot flaw                             | collector/loader (linker) | latest                                                                              |
| `lookup/vuln/<shard>.json`                      | compact cold-vuln summaries (4,096 shards) for promotion | E2B nightly               | latest                                                                              |
| `lookup/pkg/<ecosystem>/<shard>.json`           | package → advisories                                     | E2B nightly               | latest                                                                              |
| `lookup/search/<prefix>.json`                   | search index shards                                      | E2B nightly               | latest                                                                              |
| `lookup/index/<letter>.json`                    | A–Z index pages                                          | E2B nightly               | latest                                                                              |
| `jobs/<id>/…`                                   | job inputs, logs, results                                | api, E2B                  | 30 days                                                                             |

---

## 4. Shared packages

### `@ti/core`

- **Types:** `VulnRecord`, `AdvisoryRecord`, `SignalRecord`, `NoticeRecord`, `IncidentRecord`, `TechniqueRecord`, `Receipt`, `Cursor`.
- **IDs:** `normaliseId()` handles CVE, GHSA, OSV prefixes, RHSA, USN, DSA, JVNDB, EUVD and GCVE; `isCve()`; `vulnKeyFor(aliases)`.
- **Licence gates:** `canIngest(source)`, `displayMode(source)` (KV override, else the registry), and `creditsFor(sources)`, which includes the NVD notice.
- **Budget:** `reserveWrites(db, n, { priority })` does an atomic `UPDATE budget SET d1_writes = d1_writes + ? WHERE day = ? AND d1_writes + ? <= ?`. The first load stops at 1,000,000; steady updates are always counted but never blocked.
- **Time:** UTC helpers and ULIDs.

### `@ti/sources`

- One typed entry per source:
  - **Identity and pattern:** `id`, `name`, `pattern`, `cadence`, `urls`.
  - **Licence:** `licence: 'on' | 'ask' | 'wait' | 'link'`, `credit`.
  - **Handling:** `heavy` (send to E2B), `parser`, `rateLimit`.
- Validated with Zod at startup. KV can override `ingest` and `display` without a redeploy.
- Six sources ship switched off (`wait`) and two ship link-only. The repo ships the same licence statuses as the design board.

### `@ti/patterns`

```ts
export interface PatternContext {
  env: Env;
  source: SourceConfig;
  cursor: Cursor | null;
  log: Logger;
  signal: AbortSignal;
}
export interface PatternResult {
  items: RawItem[]; // ≤ 40 per call
  receipt: Receipt; // bytes to store in raw/
  nextCursor: Cursor; // committed only after writes succeed
  more: boolean; // enqueue a continuation message
  heavy?: HeavyJobRequest; // hand off to E2B instead
}
export interface Pattern {
  check(ctx: PatternContext): Promise<'unchanged' | 'changed'>;
  fetch(ctx: PatternContext): Promise<PatternResult>;
}
```

| Pattern         | How `check` works                                                                    | How `fetch` gets only what changed                                                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **git**         | GitHub `GET /repos/{o}/{r}/commits?since=` (or GitLab compare) vs cursor SHA         | Lists the changed files per commit and fetches the raw files. For one huge file (Exploit-DB CSV, Metasploit index), sets `heavy`                                                             |
| **changelist**  | `HEAD` + ETag on the change list                                                     | OSV `modified_id.csv` via `Range: bytes=0-65535`, read until the cursor timestamp. Red Hat `changes.csv` + `deletions.csv`. CSAF `changes.csv` / ROLIE                                       |
| **since**       | Cheap first-page query                                                               | NVD `lastModStartDate/EndDate` (≤ 120-day windows, 100 per page, ≤ 50 req/30 s with a key). GitHub advisories `modified=`. EUVD `fromDate`. CERT/CC by month. Washington AG Socrata `$where` |
| **fingerprint** | Conditional GET (`If-None-Match`) or `Range: bytes=0-511` for KEV's `catalogVersion` | Whole small file and diff by key. HIBP: `/latestbreach`, then `/breach/{name}`                                                                                                               |
| **feed**        | RSS/Atom `lastBuildDate` / newest GUID                                               | New items only. SEC: current 8-K Atom feed, then `Range` the filing header for `ITEM INFORMATION`                                                                                            |
| **page**        | ETag / hash of the listing section                                                   | `HTMLRewriter` with per-source selectors. Streaming, near-zero CPU                                                                                                                           |
| **heavy**       | Version or ETag check in the Worker                                                  | Creates an E2B job (section 6). The Worker never parses the file                                                                                                                             |

All patterns:

- send a declared `User-Agent` with a Motiontic ops contact (SEC requires one);
- honour `Retry-After`;
- wait between requests with `scheduler.wait()`, which uses no CPU;
- store metadata only for exploits and proofs of concept, never their code.

### `@ti/parsers`

- One module per format: CVE JSON 5 (CNA + ADP/Vulnrichment), OSV, CSAF 2.0, NVD 2.0, KEV JSON/CSV, EPSS CSV, STIX 2.1 (ATT&CK), ATLAS YAML, RSS/Atom/RDF, Exploit-DB CSV rows, Metasploit module refs, HIBP JSON, SEC 8-K header, state AG CSV/HTML rows.
- Each parser returns typed records and an `unknownFields` list, which the watchdog reports.
- The same code runs in Workers and in E2B (no Node-only imports in the parser core).

### `@ti/linker`

- **Alias graph:** a new advisory with a CVE alias attaches to that CVE. With no CVE, it keeps its own key. GCVE `correlations.json` seeds the graph on the first load.
- **Hot-set rule:** published ≥ 2024-01-01 **or** in KEV **or** has a public exploit **or** EPSS ≥ 0.1. Breaches, incidents, techniques and companies are always hot.
- **Promotion:** when a signal lands on a cold vuln, the linker reads its summary from `lookup/vuln/<shard>.json`, writes the D1 row and builds `docs/vuln/<key>.json`. No E2B call is needed.
- **Change detection:** compares the stored row with the incoming one on the fields customers act on:
  - newly in KEV;
  - first public exploit;
  - EPSS band change (bands 0–0.01, 0.01–0.1, 0.1–0.5, 0.5–1);
  - a fixed version appears;
  - CVSS change ≥ 1.0;
  - a new breach notice.

  Each change becomes one `changes` row.
- **Company matching:** SEC CIK, then domain, then normalised name + state + 30-day date window. Notices cluster into `breach_events`. Counts are kept per unit and never summed.

### `@ti/db`

- SQL migrations per database.
- Drizzle table definitions for types.
- Helpers:
  - `upsertNewer(table, rows)`: `INSERT … ON CONFLICT DO UPDATE … WHERE excluded.modified > table.modified`;
  - `batchInsert`, which respects D1's bound-parameter limit per statement (verify the current number) and ≤ 40 statements per invocation.

---

## 5. Collector Worker (`apps/collector`)

```ts
export default {
  async scheduled(event, env, ctx) {
    const due = await planner.dueSources(env, event.cron); // cadence vs last success, ingest on
    await env.JOBS.sendBatch(due.map((s) => ({ body: { sourceId: s.id, runId: ulid(), step: 0 } })));
    if (event.cron === '0 */3 * * *')
      await env.NOTIFY.send({ body: { kind: 'run-finished', at: Date.now() } });
    if (event.cron === '45 14 * * *') await watchdog.run(env);
  },
  async queue(batch, env, ctx) {
    for (const msg of batch.messages) {
      try {
        await runStep(msg.body, env);
        msg.ack();
      } catch (e) {
        msg.retry({ delaySeconds: backoff(msg.attempts) });
      }
    }
  },
};
```

A single step does the following:

1. **Load** the source config and cursor, and skip the source if `ingest` is off.
2. **Ask cheaply.** If `pattern.check()` returns `unchanged`, record the run as `unchanged` and stop.
3. **Fetch the change.** `pattern.fetch()`; if it returns `heavy`, create the E2B job (section 6) and stop.
4. **Save the receipt** to `raw/…` before parsing anything.
5. **Parse and link.** Parse at most 40 items, run them through the linker, and write the D1 upserts in one `batch()`. Each write is counted in `budget`.
6. **Update derived files:** the `docs/` and `lookup/` entries the change touches.
7. **Commit the cursor**, and only then.
8. **Continue if needed.** If `more` is set, enqueue the next step with the same run ID.

Queue settings:

- `max_batch_size: 5`;
- `max_retries: 5`, then the message goes to `ti-jobs-dlq`;
- exponential backoff.

The watchdog runs daily. It checks:

- **sources that are late:** no success in twice their cadence;
- **sharp drops:** a source's count falls by more than 20%;
- **format changes:** unknown fields appear;
- **budgets:** any budget above 80%;
- **dead-letter queue:** its depth;
- **E2B:** jobs failing.

It emails the ops address through the `send_email` binding. That is free, because the address is verified on our own account.

---

## 6. Heavy jobs on E2B (`e2b/`)

**Template:**

- `e2b.Dockerfile` installs Node 22, the DuckDB CLI and the `@ti/parsers` + `jobs` bundle, built with `e2b template build`.
- Machine size: 2 vCPU / 4 GB for daily jobs, 8 vCPU for the first load.

**Starting a job from a Worker:**

- **Primary:** the E2B JS SDK inside the Worker (`Sandbox.create(template, { envs, timeoutMs })`, then `commands.run('node /app/run.js', { background: true })`), with `nodejs_compat` on. **(verify the SDK runs in Workers)**
- **Fallback:** the E2B REST API creates the sandbox. The template's start command runs a tiny job server on a port, and the Worker POSTs the job to the sandbox's public host for that port. **(verify the REST endpoint and host format)**

**Credentials (none long-lived for writing):**

- The sandbox gets a **read-only, bucket-scoped R2 token** so DuckDB can read `raw/` and `lake/`.
- To write, it calls `POST /internal/jobs/:id/upload-urls` on the API. The call is signed with HMAC and checked against the job's allowed prefixes. The API returns presigned R2 PUT URLs (signed in the Worker with `aws4fetch`).
- When it's done, it calls `POST /internal/jobs/:id/complete` with a manifest of inbox chunks. The API enqueues `ti-load` messages and kills the sandbox.
- Every job has a hard 50-minute timeout. On the free Hobby plan a session lasts up to 1 hour.

**Jobs:**

| Job                   | When            | Does                                                                                                                       |
| --------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `first-load:<source>` | once per source | Download full history → Parquet in `lake/` → hot rows to `inbox/` → build `lookup/` shards                                 |
| `epss-diff`           | daily           | Today's 250k scores vs yesterday's (from `lake/`) → band changes for hot CVEs to `inbox/`, the full day to `lake/`         |
| `big-file:<source>`   | on change       | Exploit-DB CSV, Metasploit index, Debian JSON, Red Hat archives, ATT&CK/ATLAS/CWE/CAPEC, AIID, AIAAIC, ICO, MIT, UMD, CSIS |
| `nightly-fold`        | 02:30 UTC       | Read the day's `raw/` receipts and append them to `lake/`                                                                  |
| `search-index`        | 02:30 UTC       | Rebuild `lookup/search/*`, `lookup/index/*`, `lookup/vuln/*`, `lookup/pkg/*`, `sitemap.xml`                                |
| `compaction`          | weekly          | Merge small Parquet files                                                                                                  |
| `deep-query:<id>`     | on request      | Run an **allow-listed** query template on `lake/` and return JSON. Users never send raw SQL                                |

**Inbox format:**

- NDJSON.gz chunks of ≤ 500 rows `{ table, op, row }`.
- `manifest.json` lists each chunk with its row count and priority.

---

## 7. Loader Worker (`apps/loader`)

- Consumes `ti-load` messages, one inbox chunk each.
- Splits rows into multi-row `INSERT … ON CONFLICT` statements within the bound-parameter limit, and ≤ 40 statements per invocation.
- Before writing, it calls `reserveWrites(n, priority)`:
  - **steady-state updates** always proceed;
  - **first-load chunks** stop at 1,000,000 for the day, and the message is retried with `delaySeconds` set to midnight UTC. A message can be delayed by at most 12 h **(verify)**, so it may hop twice.
- Load order: control → techniques → signals → hot CVEs → advisories → breaches → incidents. This matches the board's first-load timeline (about 2 weeks for about 1M rows).
- Deletes the inbox chunk once it is written.

---

## 8. API Worker (`apps/api`, Hono)

**Auth**

- `@hono/clerk-auth` `clerkMiddleware()` runs on every `/v1/*` route. It reads `CLERK_SECRET_KEY` (a secret) and `CLERK_PUBLISHABLE_KEY` (a var). Webhook routes sit outside it and check signatures instead.
- `getAuth(c)?.userId` decides `access: 'preview' | 'full'`.
- Accounts are **single-user only**. Organizations are off in the Clerk dashboard and the code never reads `orgId`.

**Routes**

| Method and path                                          | Access                  | Notes                                                                                                               |
| -------------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `GET /v1/search`                                         | public                  | `q`, `type`, `sig`, `sev`, `year`, `sort`, `cursor`. Uses the search shards (below)                                 |
| `GET /v1/entries/:id`                                    | public / full           | Any alias resolves. Visitors get the **preview fields only** (title, IDs, summary, CVSS, exploited yes/no, credits) |
| `GET /v1/entries/:id/receipts`                           | signed in               | Receipts with the R2 keys and fetch times                                                                           |
| `GET /v1/index/:letter`                                  | public                  | From `lookup/index/`                                                                                                |
| `GET /v1/sources`                                        | public                  | Registry + last success + licence status                                                                            |
| `GET /v1/me` · `PATCH /v1/me`                            | signed in               | Profile (display name), alert settings                                                                              |
| `PUT /v1/me/watch/:id` · `DELETE …` · `GET /v1/me/watch` | signed in               | Per-user watchlist, alerts on/off per item                                                                          |
| `GET/POST/DELETE /v1/me/saved-searches`                  | signed in               | Saved searches                                                                                                      |
| `DELETE /v1/me`                                          | signed in               | Deletes our rows, then the Clerk user via the Backend API                                                           |
| `POST /v1/deep-query` · `GET /v1/deep-query/:id`         | signed in, rate-limited | E2B DuckDB job, allow-listed templates                                                                              |
| `POST /webhooks/clerk`                                   | Svix-signed             | `verifyWebhook(req, { signingSecret })` from `@clerk/backend/webhooks`; `svix-id` dedupe                            |
| `POST /webhooks/resend`                                  | Svix-signed             | Bounce/complaint → `email_suppressed = 1`                                                                           |
| `GET/POST /unsubscribe`                                  | signed token            | One-click unsubscribe (RFC 8058 POST)                                                                               |
| `POST /internal/jobs/:id/{upload-urls,complete}`         | HMAC                    | E2B callbacks only                                                                                                  |

**Search design.** Full-text indexes in D1 (FTS5) write many shadow rows per document, which would eat the write budget. Instead:

1. **Nightly shards:** E2B builds an inverted index of the hot set (IDs, aliases, titles, packages, tags) as `lookup/search/<2-char prefix>.json`. A query reads one shard per term and intersects the results.
2. **Live delta:** items changed since the last build are matched with `LIKE` over D1 rows where `modified > last_build`.
3. **Exact IDs** (any alias) short-circuit through the `advisories` primary key.

Cloudflare AI Search can replace this later.

**Caching and limits**

- Public responses use the Cache API with a short TTL; the cache key never includes auth. Signed-in responses are `no-store`.
- Rate limiting: per IP for public routes, per user for signed-in routes. Use the Workers rate-limiting binding if the free plan includes it **(verify)**, else a WAF rate-limiting rule **(verify free allowance)**.
- Every response carries `credits[]` for the sources used. They are shown even in previews.

---

## 9. Web app (`apps/web`, React Router v7 on Workers)

**Routes:**

- `/`, `/search`, `/e/:id`, `/index/:letter?`, `/sources`;
- `/account` with the tabs profile, watch, alerts and saved;
- `/sign-in/*`, `/sign-up/*` as full-page fallbacks.

**Server-side rendering.** Loaders call `ti-api` through the service binding. Entry previews render on the server with `<title>`, a meta description and JSON-LD, so search engines index them. `sitemap.xml` is served from R2.

**Clerk (`@clerk/react-router`):**

- `rootAuthLoader` in the root loader, with `ClerkProvider` at the root.
- `<SignedIn>`, `<SignedOut>` and `<UserButton>` in the top bar.
- **The gate:** on an entry page, when `isSignedIn` is false, the page shows the preview and calls `clerk.openSignUp({ fallbackRedirectUrl: location.href })` once per entry visit.
- **Locked actions** (Watch, Save search, Export, locked tabs) store `{ action, target }` in `sessionStorage` and open the modal. When `useAuth().isSignedIn` turns true, the stored action runs and is cleared. This is "return to intent".

**Clerk dashboard settings:**

- Organizations **disabled**;
- sign-in with email verification code, Google and GitHub; passwords **off**;
- bot protection on;
- webhook endpoint `https://api…/webhooks/clerk` for `user.created`, `user.updated` and `user.deleted`.

**Look:** Clerk `appearance` variables match the Motiontic tokens (Geist, ink `#121212`, canvas `#FAFAF8`, accent `#EF7D45`). The UI follows `platform.html` component by component: rail, top bar, results, entry tabs, the at-a-glance panel, the gate card, the account tabs.

**Admin:** `/ops` shows run health and budgets. It is visible only to Clerk user IDs listed in `ADMIN_USER_IDS`, which is not an org role.

---

## 10. Alerts and email (`apps/notify`, Resend)

1. **Collect.** At the end of every 3-hour run, the collector sends `run-finished`. `ti-notify` loads `changes` since its last cursor.
2. **Match.** For the changed entity keys, it queries `watch WHERE entry_key IN (…) AND alerts_on = 1`. This uses the index; there are no cross-database joins. It then filters by each user's triggers and writes `alert_queue` rows.
3. **Send:**
   - **Instant users** get one email per run, with all their queued changes bundled.
   - **The 03:00 UTC run** sends daily digests to `daily` users, and weekly digests to `weekly` users whose `digest_weekday` matches.
4. **Deliver** with the Resend batch API (up to 100 emails per call), using an idempotency key per user per run. `email_log` caps sends at **95 a day**. Anything over waits for the next run, and the watchdog warns at 80%.
5. **Every email has:**
   - `List-Unsubscribe` (HTTPS + mailto) and `List-Unsubscribe-Post: List-Unsubscribe=One-Click`;
   - a visible unsubscribe link;
   - a credits footer;
   - a link to each entry.
6. **Bounces and complaints:** the Resend webhook marks the address `email_suppressed`, and nothing more is sent to it.
7. **Domain:** send from `alerts@<domain>` with the SPF, DKIM and DMARC records Resend gives.

**Defaults:** `alert_frequency = 'daily'`; all five triggers on; `digest_weekday` = the weekday the user signed up.

**Upgrade path:** Resend Pro (about $20 a month for 50,000 emails; check current pricing), or Cloudflare Email Service if we move to the $5 Workers plan.

---

## 11. Security and privacy

**Secrets.** Stored with Wrangler secrets per app and never in the repo; `.dev.vars.example` lists the names. They are:

- GitHub, GitLab and NVD keys;
- E2B key;
- R2 S3 keys for presigning;
- the HMAC secret;
- Clerk keys and webhook secret;
- Resend key and webhook secret;
- the unsubscribe secret.

**Least privilege:**

- The Cloudflare deploy token is scoped to Workers, D1, R2, KV and Queues on one account.
- There are two R2 tokens: write (Workers only) and read-only (E2B).
- E2B gets no long-lived write credential.

**Verification:**

- Clerk JWTs are verified on every request.
- Webhooks are Svix-verified, with `svix-id` dedupe.
- Internal callbacks use HMAC with a timestamp (rejected after 5 minutes).

**Input safety:**

- Every external payload is parsed with Zod.
- HTML from sources is never rendered as HTML.
- Deep queries come from an allow-list only.

**Web headers:** a CSP limited to Clerk's domains, `X-Frame-Options` via `frame-ancestors`, and `Referrer-Policy`.

**Personal data:**

- We store the Clerk ID, email, name and settings. No passwords exist anywhere.
- Logs carry user IDs, not emails.
- `DELETE /v1/me` and Clerk's `user.deleted` both remove all rows.
- Users can export their data as JSON.

**Legal and data rules:**

- A privacy policy and terms (DPDP Act, GDPR) must exist before public launch.
- Licence gates are enforced in the API (ingest and display), not only in the UI.

**Supply chain:**

- Lockfile committed; Dependabot; secret scanning; CodeQL, which is free on public repos.
- GitHub Actions pinned to commit SHAs.

---

## 12. Testing

| Level              | Tool                              | What                                                                                                                           |
| ------------------ | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Unit               | Vitest                            | Every parser against recorded fixtures in `fixtures/<source>/`; ID normalisation; hot-set rule; change detection; budget maths |
| Worker integration | `@cloudflare/vitest-pool-workers` | Patterns with `fetchMock`; collector step end to end on local D1/R2/Queues; loader budget stops and resumes                    |
| Golden record      | Vitest                            | CVE-2025-3248 merged from CVE List + OSV + KEV + Metasploit + EPSS + ATT&CK fixtures equals the expected document              |
| API                | Vitest + Hono test client         | Preview vs full field sets; any alias resolves; webhook signature failures return 400                                          |
| Web E2E            | Playwright + Clerk testing tokens | Gate appears, sign-up via email code in Clerk test mode, return to intent, watchlist, delete account                           |
| Contract (live)    | manual `workflow_dispatch`        | Hits each source once and checks that its format still parses. Never scheduled as a pipeline                                   |

---

## 13. Environments and deployment

| Env        | How                                                                                                                                                                          |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Local      | Lint, typecheck and unit tests only (`pnpm build`). No local servers: running code is tested in a loop sandbox or on staging                                                 |
| Loop       | One E2B sandbox per build loop. Local `wrangler dev`, Miniflare and Workers-runtime tests are fine here; no Cloudflare or GitHub credentials, branches leave as a git bundle |
| Staging    | Resources suffixed `_staging` / `-staging`; deployed after CI passes on `main`; each branch can upload a preview of the API with `pnpm preview` and test its URL             |
| Production | Deployed on a `v*` tag or a manual run, after a reviewer approves the `production` GitHub environment; D1 migrations applied with `--remote` before Workers                  |

**CI (`.github/workflows/ci.yml`):** `pnpm install` → `pnpm lint` (Biome) → `pnpm typecheck` (`tsc --noEmit` per package) → `pnpm test` (Vitest), on every PR and push to `main`.

**Deploy:** `.github/workflows/deploy.yml` runs `scripts/deploy.mjs <staging|production>`: it fills the account-specific `${VAR}` values in each `wrangler.jsonc`, applies pending migrations, deploys consumers before producers and checks `/v1/health`. It uses a scoped `CLOUDFLARE_API_TOKEN`. The data pipeline itself runs only on Cloudflare and E2B, never in GitHub Actions.

---

## 14. Observability

- **Logs and runs:** structured JSON logs (Workers Logs, 3-day retention on free), plus the `runs` table for history.
- **Admin page:** `/ops` shows per-source last success, lag, counts, unknown fields, today's budgets (D1 writes, queue ops, R2 ops, emails), dead-letter depth and E2B jobs.
- **Alerts:** a daily watchdog email to ops, plus an immediate email when the dead-letter queue holds more than 0 messages for over an hour.

---

## 15. Milestones and acceptance criteria

| Milestone                                    | Scope                                                                                                                                                    | Done when                                                                                                                    |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **M0 Foundations**                           | Repo, CI, all Cloudflare resources, migrations, source registry, budget meter, watchdog skeleton, E2B template builds                                    | `pnpm test` is green; `wrangler deploy` works for all apps; a dummy E2B job round-trips through `upload-urls` and `complete` |
| **M1 Vulnerability core + public search**    | CVE List + Vulnrichment, NVD, OSV (GHSA, Debian, Ubuntu), KEV, EPSS (E2B), CWE; first load via E2B; search shards; web SSR previews, index, sources page | CVE-2025-3248 shows merged data from ≥ 6 sources; 3-hourly updates land within 3 h 15 min; the D1 budget is never exceeded   |
| **M2 Accounts**                              | Clerk (single-user), gate, full records, watchlist, account area, `ti_users`, Clerk webhook                                                              | Visitors get preview-only JSON; return to intent works; account deletion removes all rows and the Clerk user                 |
| **M3 Alerts + saved searches**               | `ti-notify`, Resend, digests, unsubscribe, bounce handling                                                                                               | Never more than 95 emails a day; one-click unsubscribe works; no duplicate alerts in a 7-day soak test                       |
| **M4 Exploit signals**                       | Exploit-DB, Metasploit, Nuclei, PoC repos, Project Zero, Shadowserver, ENISA, GCVE                                                                       | The evidence tab shows the separate signals for every KEV CVE                                                                |
| **M5 Breaches**                              | SEC, HHS, California, Washington, other state AGs, HIBP, VCDB, CISA advisories, company matching                                                         | Breach events group notices without summing units; SEC CIK matches ≥ 95% on a test set                                       |
| **M6 Vendors, CERTs, AI and threat context** | Red Hat, MSRC, Cisco, Oracle, BSI, CERT/CC, JVN, CERT-In; ATT&CK, ATLAS, OpenSSF malicious packages, MIT, AVID, AIAAIC, CFR, CSIS, UMD; deep queries     | All 47 automatic sources are healthy for 7 days; deep queries answer in < 30 s                                               |
| **M7 Gated sources + open-source launch**    | The 8 sources switched on as each written OK arrives; public repo, docs, security policy                                                                 | Repo public; CONTRIBUTING lets an outsider add a source with a fixture and test                                              |

---

## 16. Open-source readiness

- **Licence:** Apache-2.0 for code. Data is not included. Each source keeps its own licence, listed in `DATA_LICENSES.md`, and the code enforces it through the licence gates.
- **Brand:** the Motiontic name and logo are not covered by the code licence (`NOTICE`).
- **No secrets:**
  - `.dev.vars.example` only;
  - D1, R2 and Queues are found by name, and account-specific values in `wrangler.jsonc` are `${VAR}` placeholders;
  - forks bring their own Cloudflare, E2B, Clerk and Resend accounts.
- **Contributions:**
  - adding a source means a registry entry + parser + fixture + tests (see CONTRIBUTING);
  - ADRs in `docs/decisions/` record why we chose Cloudflare + E2B, Clerk single-user and Resend;
  - issue templates (bug, new source), a PR template, Dependabot, a Code of Conduct and a security policy are in place.
- **Not in this repo:** ARI-42 requirements and ratings, customer data, and anything under a non-public licence.

---

## 17. Risks

| Risk                                  | Mitigation                                                                                                     |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| E2B credits expire                    | Every E2B job also runs as `pnpm job <name>` on a laptop (same code), uploading through the same API callbacks |
| A source changes format               | Zod + `unknownFields` + a watchdog email; parsers are covered by fixtures                                      |
| A source disappears (like AttackerKB) | Watchdog lateness alert; the registry can switch it off without a redeploy                                     |
| D1 budget squeeze as data grows       | Hot-set rule tunable; history stays in Parquet; Workers Paid ($5) is the escape hatch                          |
| Resend's 100/day cap                  | Digest defaults, daily cap, roll-over; upgrade path documented                                                 |
| Licence breach                        | Licence gates in the API; 6 sources off and 2 link-only until written OKs                                      |
| Clerk outage                          | Public search and previews keep working without auth                                                           |

---

## 18. Verify before building

- [ ] E2B JS SDK runs inside a Worker with `nodejs_compat`; otherwise check the REST endpoint and the sandbox host format for the fallback
- [ ] D1's bound-parameter limit per statement and statements per `batch()` on the free plan
- [ ] Maximum Queue `delaySeconds` (expected 12 h)
- [ ] Workers rate-limiting binding or WAF rate-limit rule availability on the free plan
- [ ] R2 lifecycle rules on the free plan (fallback: cleanup job with free `DeleteObject`)
- [ ] Clerk free-plan monthly-user limit; `verifyWebhook` options for non-Node runtimes
- [ ] Resend free limits (3,000/month, 100/day) and the batch endpoint size
- [ ] Each source's endpoints and terms, as listed in the source analysis
