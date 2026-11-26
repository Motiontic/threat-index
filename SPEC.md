# archive-download: first-loads download a git archive to disk before reading it

## Why

A `first-load` of a git source (`shape === 'archive'`, for example `github-advisory-db` or
`openssf-malicious-packages`) reads GitHub's `.tar.gz` straight from the HTTP response while it processes each
batch. Batches wait on API calls (`processBatch` → linker reads through `/internal/jobs/:id/rows/*`). While a batch
runs, the download sits idle. Since package rows were added, batches take longer, and GitHub closes the idle
connection after a few minutes. Node's `fetch` then throws `terminated`, and the job fails.

On staging on 26 Nov 2026, three such runs failed with `terminated` 4 to 5 minutes in, while every API call they
made returned 200. The same sources loaded fine on 24 Nov.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `e2b/jobs/src/jobs/first-load.ts` (archive branch, around lines 373–400) | `fetchDocument(url)` then `readTarGz(res.body, onEntry)`; `onEntry` awaits `processBatch` inline, so reading the body pauses during each batch |
| `e2b/jobs/src/lib/download.ts` | `download(url, dest, deps)`: https only, at most 5 redirects, 3 retries on network errors and 5xx, a 1 GiB cap, and gunzip when the URL path ends `.gz`. Errors never carry the URL |
| `e2b/jobs/src/lib/tar.ts` | `readTarGz(body: ReadableStream, onEntry, { maxTotalBytes })` gunzips and parses the tar stream |
| `e2b/jobs/src/lib/work.ts` | `withScratch` gives the job a scratch directory that is removed afterwards |

## What to build

1. **Download first.** In the archive branch, download the archive to a file in the job's scratch directory before
   reading any entry. Use `download()` with two new options:
   - `gunzip: false`: keep the `.tar.gz` as it is;
   - `maxBytes: 4 GiB`: the archive cap.
   Defaults stay as they are for every other caller. Log `archive downloaded` with the byte size and duration. Never
   log the URL.
2. **Read from the file.** Open the downloaded file as a stream and pass it to `readTarGz` (add a small overload or
   helper if needed). Keep every existing limit: `maxTotalBytes`, `maxFiles`, the include globs, skipped entries over
   10 MiB, and the progress logs.
3. **Clean up.** The file lives under the scratch directory, so it is removed when the job ends, whether it succeeds
   or fails.
4. **Retries.** A download that is cut off mid-way is retried by `download()` (the existing 3 attempts with
   backoff). Processing starts only after a complete download.

Touch only `e2b/jobs/src/jobs/first-load.ts`, `e2b/jobs/src/lib/download.ts`, `e2b/jobs/src/lib/tar.ts` (only if a
file-stream entry point is needed) and their tests.

## Tests

- `download.ts`: with `gunzip: false`, the bytes on disk equal the response bytes. The new `maxBytes` is enforced.
  Defaults are unchanged.
- First-load archive path, using the existing fakes in `test-support.ts`:
  - the archive is fully downloaded before the first `onEntry` call (a fake fetch records order);
  - a body that fails half way on the first attempt and succeeds on the second gives a complete load;
  - the scratch file is gone afterwards, on success and on failure.
- All existing first-load, tar and archive-limit tests still pass.

## Not in scope

- Changing batch sizes, the linker or API reads.
- Change-list and single-file sources.
- Speeding up processing.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. In the archive path, no tar entry is read before the download finishes. Tests prove this with an ordered fake.
3. A dropped connection during download is retried, and a later attempt completes the job.
4. The downloaded archive is removed on success and on failure.
5. No log line or error message contains the archive URL.
