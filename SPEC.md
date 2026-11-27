# mcp-tasks: long package checks and deep queries as MCP Tasks

## Why

Two things don't fit in one request today:

- checking a big project: `mti_check_packages` takes at most 1,000 packages per call, so a 5,000-package
  monorepo needs five calls and the agent has to merge the answers;
- deep history queries: they run in an E2B sandbox for up to 5 minutes, far past a request's run time, so
  `mti_deep_query` isn't offered at all.

The Tasks extension (`io.modelcontextprotocol/tasks`, revision 2026-07-28) lets a `tools/call` return a task
handle at once; the client polls `tasks/get` until the task is done and reads the result from there. This
change serves that extension, uses it for checks of 1,001 to 20,000 packages and for `mti_deep_query`, and adds
the API route that cancels a deep query.

## The extension in brief (2026-07-28, as the spec and schema state it)

- **Negotiation.** The server lists `"io.modelcontextprotocol/tasks": {}` under `capabilities.extensions` in
  `server/discover`. A client declares it per request in
  `params._meta["io.modelcontextprotocol/clientCapabilities"].extensions["io.modelcontextprotocol/tasks"]`. A
  server must not return a task to a request that didn't declare it. A call that can only run as a task, and any
  `tasks/*` call, from a request that didn't declare it gets `-32021` (HTTP 400) with
  `data.requiredCapabilities.extensions["io.modelcontextprotocol/tasks"] = {}`.
- **Creating.** Only `tools/call` can become a task, and only the server decides. There is no request field and
  no per-tool declaration. The answer is `{ resultType: "task", taskId, status, statusMessage?, createdAt,
  lastUpdatedAt, ttlMs, pollIntervalMs? }`, sent only after the task is durably stored.
- **Methods.** `tasks/get { taskId }` → the task with `resultType: "complete"`; `completed` adds `result` (the
  `CallToolResult`), `failed` adds `error` (a JSON-RPC error object), `input_required` adds `inputRequests`.
  `tasks/update { taskId, inputResponses }` → empty ack. `tasks/cancel { taskId }` → empty ack, cooperative.
  There is no `tasks/list` and no `tasks/result`. The client sets `Mcp-Name` to the `taskId` on these methods.
- **States.** `working`, `input_required`, `completed`, `failed`, `cancelled`; the last three are final.
  `failed` is only for protocol errors: a tool result with `isError: true` is `completed`.
- **TTL.** `ttlMs` counts from creation. After it, the server may fail and delete the task. An unknown or expired
  `taskId` gets `-32602`.
- **IDs.** Server-made, unique, impossible to guess or enumerate. Every `tasks/*` call is authenticated and
  authorised.
- **Notifications** (`notifications/tasks` via `subscriptions/listen`) are optional; this change doesn't send
  them. Polling only.
- **Claude Code** (2.1.304+) sends the capability per request, accepts task IDs of at most 128 printable ASCII
  characters, honours `pollIntervalMs` (clamped to 250–30,000 ms), doesn't drop a task when `ttlMs` passes, and
  reads `-32602` as "unknown task".
- **SDK 2.4.0** doesn't implement the extension (no task results from tool callbacks, no `tasks/update`).
  So this change implements it in our own code, as below.

## Current state (on main)

| Area | Today |
| ---- | ----- |
| `apps/mcp/src/tasks/mcp-task.ts` | `McpTask` Durable Object; `fetch` and `alarm` throw. Bound as `MCP_TASKS`, SQLite-backed (migration tag `v1`), in production and staging |
| `apps/mcp/src/ext/tasks.ts` | `register(): void {}` |
| `apps/mcp/src/mcp.ts` | The request pipeline: size caps, parse, auth, scope `mti:read`, `KNOWN_METHODS` (no `tasks/*`), `Mcp-Name` checks for `tools/call`, then the SDK handler. One log line per request |
| `apps/mcp/src/http/body.ts` | `MAX_BODY_BYTES` 1 MiB; `MAX_SBOM_BODY_BYTES` 5 MiB (unused); `MAX_TOOL_INPUT_ELEMENTS` 4,100 |
| `apps/mcp/src/tools/mti_check_packages.ts` | Up to 1,000 packages (`maxItems` 1,000). Calls `POST /v1/packages/check`, keeps only the caller's own package text, sorts results then noRecord into one sequence, fits it to 32,000 characters and seals a cursor `{ o }` bound to the tool, the arguments and the user |
| `apps/mcp/src/tools/mti_deep_query.ts` | Stub (`enabled: false`) |
| `apps/mcp/src/cursor.ts` | `sealCursor(secret, tool, args, state, sub)` / `openCursor(...)` with the HMAC secrets |
| `apps/api/src/routes/deep-query.ts` | `POST /v1/deep-query` → 202 `{ id, status: 'running' }` (limits: 10 an hour, 3 active per user, the global job cap); `GET /v1/deep-query/:id` → `running`, `failed` (`timed_out`, …) or `complete` with `result { template, rows, rowCount, truncated, sources, scanned, tookMs }` and `credits`. `DELETE /v1/deep-query/:id`: stub (501). Owner checks via `deepOwner`. `killLater(c, sandboxId, jobId)` kills a sandbox after the response |
| `apps/api/src/lib/deep-templates.ts` | Templates `cve-history`, `package-advisories`, `epss-history`, `company-breaches`, `kev-additions`, each with typed, pattern-checked parameters |
| `apps/api/src/lib/e2b.ts` | Only `affected-backfill` sandboxes are limited to the API host (`network.allowOut`); deep-query sandboxes are not |
| `apps/api/src/lib/mcp-routes.ts` | `POST /v1/deep-query`, `GET` and `DELETE /v1/deep-query/:id` are allowed for MCP with `mti:read` |
| ti-api `POST /v1/packages/check` | Counts packages per user per day in `package_usage` (20,000 a day), fails closed |

## What to build

### 1. Where the code goes

- `apps/mcp/src/ext/tasks.ts`: negotiation helpers (`declaresTasks(params)`), the `-32021` error, the
  `server/discover` capability entry, and the handlers for `tasks/get`, `tasks/update`, `tasks/cancel`.
- `apps/mcp/src/tasks/mcp-task.ts`: the Durable Object.
- `apps/mcp/src/tasks/*.ts`: task records, ID generation, the check runner, the deep-query runner.
- `apps/mcp/src/tools/mti_check_packages.ts`: the task path and task cursors.
- `apps/mcp/src/tools/mti_deep_query.ts`: the tool.
- `apps/api/src/routes/deep-query.ts`, `apps/api/src/lib/e2b.ts`: the cancel route and the sandbox egress limit.
- Keep edits to `mcp.ts`, `server.ts`, `http/body.ts` and `tools/shared.ts` small (other changes touch them
  too). Call ti-api from the task code with `callApi` directly rather than extending `apiJson`.

Because the SDK can't return a task from a tool callback or serve `tasks/update`, the pipeline handles these
itself, after every existing check (size caps, auth, scope, `Mcp-Name`, origin) and before the SDK:

- `tasks/get`, `tasks/update`, `tasks/cancel`: answered by `ext/tasks.ts`. Add them to `KNOWN_METHODS` (which
  only labels logs). Header checks: see "Decisions added at review" item 3.
- A `tools/call` that will become a task (rules below): validated exactly as the SDK path would (the tool's
  off-switch, its JSON Schema through the same validator, `findBadText`), then answered by `ext/tasks.ts`.
  Everything else stays on the SDK path.
- `server/discover`: the answer lists `"io.modelcontextprotocol/tasks": {}` under `capabilities.extensions`,
  through the server's capabilities option (SDK `ServerCapabilities` has `extensions`). `ext/tasks.ts` exports
  `capability()`, merged into `capabilities.extensions` in one line of `server.ts`; never replace the object
  (the skills extension adds its own entry).

Every answer leaves through the existing `send`/`finish` path, with the usual headers and one log line.

### 2. Storage: one Durable Object per user

- `MCP_TASKS.idFromName('user:' + sub)`. All of a user's tasks live in that user's object. A task ID sent by
  another user reaches that other user's object and is simply not found. The object also stores the owner `sub`
  with each task and checks it on every call.
- Task ID: 16 random bytes (128 bits) from `crypto.getRandomValues`, Crockford base32, 26 characters, matching
  `^[0-7][0-9A-HJKMNP-TV-Z]{25}$` exactly. The ID alone grants nothing.
- Per task (SQLite): id, kind (`check` | `deep_query`), status, statusMessage, createdAt, lastUpdatedAt,
  expiresAt, the caller's identity for API calls (sub, scopes, clientId), the input needed to run it, progress,
  and the result. Big results are stored in pieces (one row per 1,000-package chunk), each well under 2 MB.
- Caps per user: at most 3 tasks in `working` at once (a 4th gets the tool error `too_many_tasks`: "You have 3
  tasks running. Wait for one to finish."), and at most 20 stored tasks (a 21st also gets `too_many_tasks`;
  nothing is deleted before its `ttlMs`).
- `ttlMs` = our maximum run time for the kind plus one hour, from creation: checks 1,800,000 + 3,600,000 =
  5,400,000 (90 minutes); deep queries 600,000 + 3,600,000 = 4,200,000 (70 minutes). The object deletes each task
  and its result at `expiresAt` (alarm scheduling: "Decisions added at review" item 1); after that `tasks/get`
  gets `-32602`. Nothing about a task outlives it.
- The task is written to the object before the `resultType: "task"` answer is sent.

### 3. Big checks: `mti_check_packages`

- Input: `maxItems` becomes 20,000. `packages` becomes optional; a call has either `packages` or a task
  `cursor` (below), not neither.
- Size caps for `tools/call` named `mti_check_packages` (known from `Mcp-Name` before parsing): body 3 MiB.
  `MAX_TOOL_INPUT_ELEMENTS` becomes 80,100. Other tools keep 1 MiB.
- Up to 1,000 packages: answered as today, with or without the Tasks capability.
- 1,001 to 20,000 packages:
  - request declared Tasks → becomes a task;
  - request didn't → tool error `too_many_packages`: "Send at most 1,000 packages per call, or use a client
    that supports MCP tasks." (no `-32021`: the work can be split).
- The runner (in the user's object, driven by alarms): sends the list to `POST /v1/packages/check` 1,000 at a
  time with the signed identity of the task's owner (fresh assertion per call, request ID
  `<taskRequestId>-<chunk>`). Each alarm does at most 5 chunks or 60 seconds, saves progress after each chunk,
  and sets the next alarm at once. A retried alarm resumes from the saved progress.
- Errors: a 429 (daily quota or rate) or 403 `blocked` ends the task `completed` with the matching tool error
  (`isError: true`); so do ti-api being down after 3 tries a chunk, and the 30-minute maximum run time (tool
  error `timeout`). `failed` only for an internal fault, with a `-32603` error object.
- The merged answer: `checked` and `matched` summed; `summary` summed; `results` in priority order then input
  order; `noRecord`; `rejected` with indexes shifted to the full list; `asOf` the oldest chunk's; credits
  merged. Only the caller's own package text goes out, exactly as on the normal path (move that code into a
  shared `formatCheck` used by both).
- `tasks/get` on a completed check returns `result` = the first page as a normal `mti_check_packages` result,
  fitted to 32,000 characters, with `nextCursor` when more remains.
- Task cursors: sealed with the existing `sealCursor`, bound to the tool, the user and the arguments `{}`, with
  state `{ t: taskId, o: offset }` (`o` 0–20,000). `mti_check_packages({ cursor })` with a task cursor reads
  the next page from the user's object (synchronously, no new task). A tampered or foreign cursor, a cursor for
  an expired task, or a task cursor sent with other arguments gets the same JSON-RPC -32602 (`field: cursor`)
  that mcp.ts's cursor check gives today. Extend that check (`validState`) to accept `{ t, o }`.
- `pollIntervalMs`: 10,000.

### 4. `mti_deep_query`

- Enabled here. Scope `mti:read`. Hints: `readOnlyHint true, destructiveHint false, idempotentHint false,
  openWorldHint false`. Title "Deep history query".
- Input: `{ template, params }`: `template` one of the five template names; `params` an object of strings (at
  most 4 keys, each value at most 214 characters, no control characters). The API does the full check; its 400
  becomes `invalid_argument`.
- Always a task:
  - request didn't declare Tasks → `-32021` with `requiredCapabilities` (HTTP 400);
  - otherwise `POST /v1/deep-query`; a 429 or 400 there is answered at once as a normal tool error (no task);
  - on 202 the task is stored with the deep-query job id, then the task answer is sent.
- The runner polls `GET /v1/deep-query/:id` every 15 seconds by alarm. `complete` → `completed` with the
  result; `failed` (including `timed_out`) → `completed` with a tool error naming the public error code. Our
  maximum run time is 10 minutes, after which the runner cancels the job (below) and completes with `timeout`.
- Result: `{ asOf, template, rowCount, truncated, rows, credits, notes }`. Every string in `rows` comes from
  outside sources: rows sit under `untrusted`, each string goes through `clean()` with the title cap, keys are
  kept only if they match `^[a-z][a-z0-9_]{0,40}$`, numbers and booleans pass, nested objects and arrays are
  dropped. Fitted to 32,000 characters with a task cursor for the rest, as in section 3 (the cursor names
  `mti_deep_query`; a call with only `cursor` reads the next page).
- `pollIntervalMs`: 20,000.

### 5. `tasks/get`, `tasks/update`, `tasks/cancel`

- All three need the Tasks capability on the request (else `-32021`), sign-in and `mti:read`.
- `params.taskId` must be a 26-character Crockford base32 string; anything else → `-32602`.
- `tasks/get` → `{ resultType: "complete", taskId, status, statusMessage?, createdAt, lastUpdatedAt, ttlMs,
  pollIntervalMs, result? | error? }`. Unknown, expired or another user's → `-32602` with the same message in
  every case.
- `tasks/update` → our tasks never ask for input, so no keys are ever outstanding: ignore them and return the
  ack `{ resultType: "complete" }` for an existing task; `-32602` otherwise. Never `input_required` inside a
  task.
- `tasks/cancel` → ack `{ resultType: "complete" }`. A working check stops after the chunk in flight and becomes `cancelled`. A working
  deep query calls `DELETE /v1/deep-query/:id`, then becomes `cancelled`. A finished task is left as it is.
- `notifications/cancelled` for a task is ignored. Disconnecting doesn't cancel a task (that is the point of a
  task); non-task calls still abort on disconnect as today.

### 6. API: cancel a deep query, and limit its sandbox (`apps/api`)

- `DELETE /v1/deep-query/:id`, owner only (another user's or an unknown id → 404, same body):
  - if the job is `starting` or `running`: mark it finished as cancelled (use the existing status values: a
    `failed` row with error `cancelled`, unless the jobs table already allows a `cancelled` status; don't
    rebuild the table), then kill its sandbox after the response with `killLater` → 200 `{ status:
    'cancelled' }`;
  - if it already finished → 200 `{ status }` with its current status.
- `GET /v1/deep-query/:id` reports a cancelled job as `failed` with error `cancelled`.
- Deep-query sandboxes may reach only the MTI API host: the job reads the lake only through the API
  (`/objects`, `/list`). Set `network.allowOut: [apiHost]` with everything else denied, as `affected-backfill`
  does. DuckDB must not fetch extensions at run time (autoload would call extensions.duckdb.org): confirm the
  json and parquet extensions are built in or pre-installed in the jobs template, and turn off
  `autoinstall_known_extensions` in the job. Say in PROOF.md what was checked.

### 7. Logs and privacy

- Task log lines carry the task kind, status, chunk counts and timings, and the first 6 characters of the task
  ID. Never the full task ID, never `sub` or the client ID, never package names.
- The privacy page (`apps/web`) gets one sentence: results of long checks are kept for up to 90 minutes so
  the client can fetch them, then deleted.

## Tests

- Negotiation: `server/discover` lists the extension; `tasks/get`, `tasks/update`, `tasks/cancel` without the
  capability → `-32021` (HTTP 400, `requiredCapabilities`); `mti_deep_query` without it → `-32021`; a
  2,000-package check without it → `too_many_packages`; a 500-package check with it → a normal result, no
  task.
- Task answer shape: `resultType: "task"`, 26-character ID, `ttlMs` 5,400,000, `pollIntervalMs`, ISO times;
  the object holds the task before the answer is sent (the fake records order).
- Lifecycle with a fake ti-api: a 5,000-package check runs through alarms to `completed`; the merged answer
  equals five 1,000-package answers merged by hand; paging through task cursors returns every result once; a
  retried alarm after a failure mid-chunk doesn't duplicate or skip; 429 mid-way → `completed` with
  `rate_limited`; the 30-minute limit → `completed` with `timeout`.
- Isolation: user B's `tasks/get`, `tasks/cancel` and task cursor for user A's task → `-32602` /
  `invalid_argument`, identical to a random ID; a malformed ID → `-32602`; a tampered cursor refused.
- Caps: a 4th working task → `too_many_tasks`; a 21st stored task → `too_many_tasks`, and nothing is deleted
  before its `ttlMs`.
- Expiry: after 90 minutes the alarm deletes the task and its result; `tasks/get` → `-32602`.
- Cancel: a working check stops and becomes `cancelled`; a working deep query calls the API DELETE and becomes
  `cancelled`; cancelling a finished task changes nothing.
- `tasks/update` on an existing task → empty ack and no state change.
- Deep query: rows with markdown, links, instruction text and odd keys come out cleaned, under `untrusted`,
  with bad keys dropped; an API 429 is answered at once as a tool error.
- API: DELETE by the owner of a running job marks it cancelled and kills the sandbox (fake launcher); by
  another user → 404; on a finished job → its status; GET after cancel → `failed` / `cancelled`. Deep-query
  sandboxes are created with `allowOut` set to exactly the listed hosts.
- Size caps: a 3 MiB `mti_check_packages` body is accepted; 3 MiB + 1 is refused; another tool's 1 MiB + 1 is
  refused.
- Logs: no full task ID, `sub`, client ID or package name in any task log line.

## Not in scope

- `notifications/tasks` and `subscriptions/listen` for tasks.
- `input_required` inside a task.
- SBOM checks (`mti_check_sbom`), the report app.
- A queue: the work runs in the user's Durable Object by alarm, so a task's state and its work share one
  strongly consistent store, and no new Cloudflare resource is needed.

## Acceptance criteria

1. `pnpm build` and the Workers tests pass; the lockfile is unchanged; no new Cloudflare resource is needed.
2. A client that declares Tasks can check 1,001 to 20,000 packages in one call; one that doesn't gets a clear
   "split the list" answer.
3. `mti_deep_query` runs only as a task, and `-32021` names the missing capability otherwise.
4. Another user can't read, page or cancel a task; the ID alone grants nothing.
5. Cancelling a deep query stops its sandbox; deep-query sandboxes reach only the hosts listed.
6. Task results are gone 90 minutes after creation.
7. After deploy, on staging (checked by hand, outside the loop): a 5,000-package list finishes in under 2
   minutes.

## Decisions added at review

These sharpen the sections above. Where they differ, this section wins.

1. **One alarm per object.** A Durable Object has one alarm; `setAlarm` replaces it.
   - Each task row has `nextRunAt` (working tasks) and `expiresAt` (all tasks).
   - The single alarm is set to the earliest of those.
   - `alarm()` runs every due task. It catches errors per task (3 faults in a row → `failed` with -32603),
     deletes expired rows, and re-arms in `finally`.
   - Every call into the object first deletes rows with `expiresAt <= now`, and re-arms if `getAlarm()` is null.
   - Reads treat `expiresAt <= now` as unknown.
   - Time comes from an injectable `now()`.
2. **Row size.** DO SQLite caps a value at 2 MB.
   - Store the input as one row per 1,000 packages.
   - Store only cleaned, formatted output, never raw API bodies, in rows of at most 1 MB.
   - Read upstream with byte caps: 4 MiB per check chunk, 5 MiB per deep-query result.
   - A test uses a 3 MB chunk answer.
3. **Intercept only modern requests, and repeat the SDK's header checks.**
   - The pipeline intercepts only 2026-07-28 requests. A 2025-era `tasks/*` call, or a 2025-era `mti_deep_query`,
     gets -32021.
   - Before intercepting, repeat the checks the SDK would make:
     - `MCP-Protocol-Version` equals the envelope revision;
     - `Mcp-Method` equals the method;
     - `Mcp-Name` is present and equals `params.name` (tools/call) or `params.taskId` (tasks/*).

     Failures get -32022 or -32020 with HTTP 400, as the SDK path does. -32602 answers are HTTP 200.
   - Each check has a test on the intercept path.
   - The intercept is one call, placed after `log.toolsHash`.
4. **Results carry `resultType`.**
   - Every answer the pipeline builds has `resultType`: `"task"` on the task-created answer, and `"complete"`
     on `tasks/get` and on the two acks.
   - A -32021 answer echoes the request's `id`.
5. **Request IDs for API calls.**
   - At creation, `taskRequestId = crypto.randomUUID()`. Never use the task ID or a client-supplied ID for this.
   - Calls use `<uuid>-c<n>` (check chunks), `-p<n>` (deep-query polls) and `-x` (cancel). These match ti-api's
     `^[A-Za-z0-9-]{8,64}$`.
   - Each call has `AbortSignal.timeout(25_000)`.
6. **Deep-query API answers, mapped at once (no task created).**
   - 409 `query_running` (one active deep query per user) → `too_many_tasks`
   - 429 → `rate_limited`
   - 400 → `invalid_argument`
   - 502 or 503 → `upstream_unavailable`
   - 501 → `not_available_yet`
7. **Reserve, then launch.**
   - The cap check and the insert of a `working` row happen in one synchronous step in the object. Only then
     does the code call `POST /v1/deep-query` or start the first chunk.
   - On anything but 202, delete the reservation and answer the tool error.
   - On 202, store the job ID, then answer.
8. **Transitions are conditional.**
   - Every status change is `UPDATE … WHERE status = 'working'`.
   - Cancel sets `cancelled` at once. An answer still in flight is dropped.
   - For a deep query, the object retries `DELETE /v1/deep-query/:id` by alarm until it gets 200 or 404 (up to
     the task's expiry).
   - The API writes `status = 'failed', error = 'deep-query: cancelled'` and adds `cancelled` to `DEEP_ERRORS`,
     so `GET` reports `failed` / `cancelled`.
9. **Quota and rate limits during a check.**
   - On `quota_exceeded`, complete with the merged partial result, `truncated: true` and the note "Daily limit
     reached after N packages."
   - On a 429 rate limit, wait for `Retry-After` (by alarm) and continue, within the run time.
   - PROOF.md notes the small double-charge window: a crash after a charged chunk, before its progress is saved.
10. **Identity lifetime.**
    - Store the token's `expiresAt` with the task. Make no API call after it: complete with `timeout` and the note
      "Sign-in expired."
    - Clear the stored scopes and client ID when a task leaves `working`.
    - A blocked or deleted user's next API call fails, and the task ends with that tool error.
    - The privacy sentence covers deleted accounts: their task results expire within the same 90 minutes.
11. **Page everything.**
    - `rejected` is paged in the same sequence as results and noRecord, not all on page 1.
    - Each stored page is checked against the tool's outputSchema with the same validator. A failure ends the
      task `failed` with -32603.
12. **Body cap.**
    - After parsing, a body over 1 MiB gets 413 unless it is `tools/call` for `mti_check_packages`, whose cap is
      3 MiB.
    - The tool's description says "up to 20,000 packages or 3 MiB".
13. **Shared code with the parallel changes.**
    - `ToolDef` gains optional `scope?: 'mti:read' | 'mti:watch'` (default `mti:read`) and
      `hints?: Partial<typeof HINTS>` (merged over `HINTS`). The watch change adds exactly the same fields, so
      whichever lands second rebases trivially.
    - New `ToolErrorCode`s here: `too_many_tasks`, `too_many_packages`. Both changes add to the union.
    - Don't touch `mcp-routes.ts` or `instructions.ts`. The skills change writes the instruction lines for
      `mti_check_packages` (task support) and `mti_deep_query`.
14. **Cursor-only calls.** A cursor-only `mti_deep_query` call reads a stored page and doesn't need the Tasks
    capability.
15. **Timed tests** write past timestamps and then call `runDurableObjectAlarm`; nothing waits in real time.

## Answers to the build's questions (round 2)

1. **21st stored task:** refuse with `too_many_tasks` and never delete a task before its `ttlMs`, as built. The
   Tests line saying "evicts the oldest finished one" was wrong and is corrected above.
2. **Privacy page:** there isn't one in `apps/web`. Drop that item from this change. The retention sentence will
   go on a privacy page that is written separately. Keep the suggested sentence in PROOF.md.
3. **Instructions check:** keep `mti_deep_query` skipped in the "INSTRUCTIONS names every enabled tool" test for
   now. The skills change, which lands first, writes that line. When this branch is rebased onto it, remove the
   skip.

Carry on to review and QA.

## Changes from the first build (round 3)

An independent review of the build found the items below.

**Rebase first.** Start by rebasing `feat/mcp-tasks` onto the latest `origin/main`, where the skills change
(#61) has merged:
- keep both sets of `KNOWN_METHODS`;
- keep the async `buildServer`, and merge the Tasks capability into `capabilities.extensions` without replacing
  the skills entry;
- remove the `mti_deep_query` skip from the "INSTRUCTIONS names every enabled tool" test (the line now exists).

Then fix:

1. **Deep-query rows are nested** (blocker). The job emits `{ source, jobId, record: { ... } }` for
   `cve-history`, `package-advisories`, `company-breaches` and `kev-additions`, so today's formatter returns
   empty rows.
   - Flatten `record` one level, using a per-template allow-list of fields, taken from what the job actually
     writes. Examples: key or ID, aliases (joined, capped), summary, published, modified, firstSeen, kind,
     severity, company, records.
   - Each string goes through `clean()`.
   - Drop `jobId`.
   - Add a test per template that uses the job's real row shape, taken from `e2b/jobs/src/jobs/deep-query.ts`
     and its tests, not hand-made flat rows.
2. **No free storage from duplicates or bad entries.**
   - Deduplicate the input (same ecosystem, name and version, or the same purl) when the task is created. The
     answer notes how many were merged.
   - Store at most 1,000 rejected entries per task, plus a count of the rest.
3. **No needless re-charging.**
   - A 200 whose body is over the byte cap is never retried. Its packages are listed as not checked (reason
     `answer_too_large`), and the task carries on.
   - After a timeout, retry that chunk at most once (2 tries in all).
   - When a task ends on a terminal error (`upstream_unavailable`, `timeout`, `blocked`), complete with the
     merged partial result, `truncated: true` and a note, as the quota path does. Never throw away finished
     chunks.
   - PROOF.md documents the remaining double-charge cases (a crash after a charge, and a timeout after a
     charge).
4. **The intercept path is as strict as the SDK.** Before intercepting, require:
   - `jsonrpc: '2.0'`;
   - a string or number `id` (a notification is never intercepted; `tasks/cancel` as a notification does
     nothing);
   - `_meta` protocol revision exactly `2026-07-28`, otherwise -32021 for `tasks/*` and `mti_deep_query`;
   - the element cap;
   - the tool's `enabled` flag.

   A `taskId` that isn't a string gets -32602.
5. **Chunks fit ti-api's body cap.** Split chunks by size as well as count: at most 1,000 entries and at most
   900 KB serialised.
6. **Stopping a deep-query cancel.**
   - 401 and 403 answers to the DELETE are final.
   - Stop retrying at the token's expiry.
   - Clear the stored identity as soon as the task leaves `working`, or when cancel retries stop.
7. **Expiry and cost.**
   - Validate each output item against the schema when it is written, not by re-paging everything at the end.
   - Store the item count.
   - Page by key, not OFFSET.
   - Count input rows with `COUNT(*)` rather than loading them.
   - Keep each alarm's work bounded, so the alarm can't die from CPU or memory before re-arming.
8. **Deep-query body cap** = the job's result cap plus 64 KiB, so a near-limit result can still be read.
9. **`mti_deep_query` requires `template`** in its schema. The intercept path checks the schema before reserving
   a slot or calling the API.
10. **Egress and DuckDB.**
    - Add the same `checkEgress` probe that `affected-backfill` uses to the deep-query job, so the claim in
      `apps/api/src/lib/e2b.ts` is true.
    - In `e2b/e2b.Dockerfile`, add a build step that runs
      `duckdb -c "select extension_name, loaded, installed from duckdb_extensions()"` and fails the build
      unless `json` and `parquet` are available without a download.
    - PROOF.md records what was checked.
11. **Small fixes.**
    - A failed task's `tasks/get` text names the task's own request ID, not the poll's.
    - The tool off-switch (`mcp:tool:<name>:off`) also stops running tasks: the alarm checks it before each
      chunk or poll and completes with `tool_off`.
    - The 80,100 element cap applies only to `tools/call` for `mti_check_packages`. Every other request keeps
      4,100, enforced in the pipeline before the SDK.
