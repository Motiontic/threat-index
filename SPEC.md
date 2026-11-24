# archive-limits: let large repository archives load

## Why

The first-load job reads a source's repository archive as a stream and stops with "archive has too many files"
once it passes a fixed file-count cap. The CVE List repository (`CVEProject/cvelistV5`) holds about 300,000
JSON files, so its first load fails on staging, and CVE titles and summaries never arrive. The cap protects
memory and time; it should be set per source, not fixed for all.

## What to build

1. Read the archive reader in `e2b/jobs/src/` (the git-archive path of `first-load`) and find the file-count and
   size caps. Keep safe defaults for every source.
2. Add optional `pull.git.maxFiles` and `pull.git.maxBytes` to the source config type (in
   `packages/sources/src/pull.ts`), read by the archive reader; a source may raise the cap up to a hard ceiling
   (1,000,000 files and 20 GiB uncompressed).
3. Set `maxFiles: 400000` on `packages/sources/src/sources/cve-list.ts` (the CVE List has ~300k files).
4. Make sure memory stays bounded for that size: files are parsed and turned into inbox chunks as they stream,
   never all held at once; parsed records for the lake are written in batches; only hot rows go to the inbox.
   Count only files that match the include globs against the cap; skip others without reading their bodies.
5. Progress logs every 10,000 files (count and elapsed time only).
6. Tests: a synthetic archive over the default cap fails without the override and passes with it; memory test
   or reasoning saved as proof that the reader holds at most one file body at a time.

## Not in scope

Other sources' caps, the loader, migrations, new dependencies.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. The tests in section 6 pass.
3. `cve-list.ts` sets `pull.git.maxFiles: 400000`, and no other source file changes.

## Changes from the first build of this branch

The premise was wrong in its detail: `MAX_KEPT_FILES` is already 400,000. Yet the real staging job for
`cve-list` failed with exactly `archive has too many files`. Find the real cause:

1. Grep for every place that emits `archive has too many files` (the tar reader in `e2b/jobs/src/` and the
   first-load job) and list each cap and what it counts (all tar entries including directories and files the
   include globs reject, or only kept files).
2. Download the real archive in the sandbox
   (`curl -sL https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main -o /tmp/cve.tgz`), count
   its entries (`tar tzf /tmp/cve.tgz | wc -l`), the entries matching `cve-list`'s include globs, and its
   unpacked size. Save the numbers as proof.
3. Fix so that this archive loads: caps that count entries the include globs reject should not count them (or
   should allow far more of them), the unpacked-size cap must fit it, and a source can raise caps up to the hard
   ceiling through `pull.git.maxFiles` / `pull.git.maxBytes`. Set `cve-list`'s values from the measured numbers,
   with headroom. Replace section 6's test with one built from these real numbers on a synthetic archive.
4. Prove it: run the git-archive path of `first-load` locally in the sandbox against the real downloaded
   archive with a fake API (no network writes), and show it reads every matching file without hitting a cap.

Re-run every acceptance check (criterion 3 becomes: `cve-list.ts` sets the measured caps).
