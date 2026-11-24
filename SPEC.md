# job-memory: the search index job must finish on the real data set, and a crashed job must say so

## Why

After `search-scale`, the nightly `search-index` job dies on staging (211,000 hot entries). Measured on
24 Nov 2026 in the job sandbox:

1. The index builds: `"msg":"index built","rows":210791,"shards":5512,"largestShardBytes":3144099,
   "letterPages":434`. Right after that log line Node aborts with
   `FATAL ERROR: Ineffective mark-compacts near heap limit … JavaScript heap out of memory` at about 2,040 MB.
   The job turns every shard and letter page into a string and holds them all in one `files` array before
   uploading. 5,512 shards of up to 3 MB each is several GB.
2. The heap limit was Node's default (about 2 GB), although `e2b/e2b.Dockerfile` sets
   `ENV NODE_OPTIONS=--max-old-space-size=3072`. Commands started through the E2B SDK
   (`apps/api/src/lib/e2b.ts`, `sbx.commands.run('node /app/run.mjs', …)`) do not get the image's `ENV`.
3. When Node aborts, nothing reports back. The job row stays `running` for good, and the same-day duplicate
   check then refuses to start another `search-index` job.

## What to build

1. **Bounded memory in the writer** (`e2b/jobs/src/jobs/search-index.ts`). Serialise and upload one shard or
   letter page at a time (a small fixed number in flight, as today's upload concurrency), and release each
   string after its upload. Nothing may hold all serialised objects at once. Look for other large duplicates
   too (docs copied into many shards as separate objects, the size estimate that stringifies a shard more than
   once) and remove what is cheap to remove. The manifest is still written last.
2. **Total index size.** Log the total bytes and object count written. If docs are stored inline in every
   shard that references them, measure what that costs on the synthetic 250,000-entry build and, if the total
   is more than about 1 GB, store each doc once (for example in doc shards keyed by entry-key prefix that the
   API reads for the final page of hits only) while keeping at most a small, fixed number of R2 reads per
   query. Keep the API able to read the layout this job writes; bump the layout version if it changes so old
   objects are never read, and delete objects of superseded layouts after a successful build.
3. **Heap flag where it takes effect.** The launch command sets the heap itself, for example
   `node --max-old-space-size=<n> /app/run.mjs`, sized below the template's memory
   (`e2b/build-template.mjs`). Remove or correct the `ENV NODE_OPTIONS` line and its comment so the Dockerfile
   does not claim something that does not apply. Child processes must still not inherit the job key.
4. **A crashed job reports failure.** If the job process exits abnormally (out of memory, uncaught error,
   signal), the job row must end `failed` with a short reason. Pick the simplest reliable design, for example
   a tiny wrapper that runs the job as a child process and calls the existing failure route when the child
   exits non-zero without having reported, or handling in the API for jobs whose sandbox is gone. The wrapper
   must keep the per-job key out of any grandchild's environment.
5. **A stale `running` job does not block the next one.** The duplicate check for day-scoped jobs treats a
   `running` job older than the job time limit (`JOB_TIMEOUT_MS`) as failed: it marks it `failed` with reason
   `timed out` and lets the new job start.
6. **Tests.**
   - Writer: the 250,000-entry synthetic build runs with the Node heap capped at 1,536 MB (spawn the build in
     a child process with `--max-old-space-size=1536`) and records peak heap, total bytes and object count in
     the proof.
   - Runner: a job that exits non-zero without reporting ends `failed` through the wrapper (fake API).
   - API: a stale `running` day-scoped job is marked failed and a new one starts; a fresh `running` one still
     blocks.
7. Update `e2b/README.md` and the search design notes with the limits and the measured numbers.

## Not in scope

Ranking, D1 full-text search, other jobs' logic, migrations, new dependencies, `pnpm-lock.yaml`.

## Files this loop owns

`e2b/jobs/src/` (the search-index job, `run.ts`, a wrapper and their tests), `e2b/e2b.Dockerfile`,
`e2b/build-template.mjs`, `e2b/README.md`, `apps/api/src/lib/e2b.ts`, `apps/api/src/lib/search-engine.ts`,
`apps/api/src/routes/internal-jobs.ts`, `packages/core/src/search*.ts`, `packages/core/src/r2-keys*.ts`,
their tests under `apps/api/test/`, and `docs/`.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. The tests in section 6 pass; the proof gives peak heap, total index bytes and object count for the
   250,000-entry build.
3. No code path collects every serialised index object in memory.
