import { appendFileSync, createReadStream } from 'node:fs';
import { Readable } from 'node:stream';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { createGzip } from 'node:zlib';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import {
  archiveLimits,
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_FILES,
  run as firstLoad,
  HARD_MAX_BYTES,
  HARD_MAX_FILES,
} from './jobs/first-load.ts';
import { fakeApi, fakeCtx, job, makeTar, noSleep } from './test-support.ts';

const evidence = (line: string) => {
  const file = process.env.EVIDENCE_FILE;
  if (file) appendFileSync(file, `${line}\n`);
};

const REPO = 'CVEProject/cvelistV5';
const ARCHIVE = `https://github.com/${REPO}/archive/${'c'.repeat(40)}.tar.gz`;
const base = { duckdb: () => null, sleep: noSleep, now: () => new Date('2026-11-24T00:00:00Z') };
const cve = SOURCE_BY_ID.get('cve-list') as NonNullable<ReturnType<typeof SOURCE_BY_ID.get>>;

// Measured on the real archive, 2026-11-24 (proof/archive-measure.txt).
const REAL = { entries: 431_634, dirs: 663, matching: 430_969 };

/** Lazily writes a gzipped tar of `matching` CVE files plus the non-matching rest, never holding it all. */
function syntheticArchive(matching: number, others: number): ReadableStream<Uint8Array> {
  const body = fixture('cve-list', 'rejected.json');
  const one = (path: string, data: string, type = '0') => makeTar([{ path, data, type }], { end: false });
  async function* chunks() {
    yield one('cvelistV5-main/', '', '5');
    const batch: Buffer[] = [];
    const flush = () => Buffer.concat(batch.splice(0));
    for (let i = 0; i < matching; i++) {
      const year = 1999 + (i % 27);
      batch.push(one(`cvelistV5-main/cves/${year}/${i % 1000}xxx/CVE-${year}-${i}.json`, body));
      if (batch.length === 500) yield flush();
    }
    for (let i = 0; i < others; i++) batch.push(one(`cvelistV5-main/cves/note-${i}.txt`, 'x'));
    batch.push(Buffer.alloc(1024));
    yield flush();
  }
  return Readable.toWeb(
    Readable.from(chunks()).pipe(createGzip({ level: 1 })),
  ) as unknown as ReadableStream<Uint8Array>;
}

const serve = (body: () => ReadableStream<Uint8Array>) =>
  (async () => new Response(body() as BodyInit)) as unknown as typeof fetch;

describe('archiveLimits', () => {
  it('uses safe defaults, honours a source, and stops at the hard ceilings', () => {
    expect(archiveLimits({})).toEqual({ maxFiles: DEFAULT_MAX_FILES, maxBytes: DEFAULT_MAX_BYTES });
    expect(archiveLimits({ maxFiles: 600_000, maxBytes: 6 * 1024 ** 3 })).toEqual({
      maxFiles: 600_000,
      maxBytes: 6 * 1024 ** 3,
    });
    expect(archiveLimits({ maxFiles: 5e9, maxBytes: 1e15 })).toEqual({
      maxFiles: HARD_MAX_FILES,
      maxBytes: HARD_MAX_BYTES,
    });
    expect(archiveLimits({ maxFiles: -1, maxBytes: Number.NaN })).toEqual(archiveLimits({}));
    expect(HARD_MAX_FILES).toBe(1_000_000);
    expect(HARD_MAX_BYTES).toBe(20 * 1024 ** 3);
  });

  it('sets cve-list caps above the measured archive', () => {
    const git = cve.pull?.git;
    expect(git?.maxFiles).toBeGreaterThan(REAL.matching);
    expect(git?.maxBytes).toBeGreaterThan(3_631_342_040);
  });
});

describe('a CVE-List-sized archive (real counts, synthetic bodies)', () => {
  const others = REAL.entries - REAL.dirs - REAL.matching;

  it('fails with "too many files" under the default cap and loads with the cve-list override', async () => {
    const git = cve.pull?.git as NonNullable<NonNullable<typeof cve.pull>['git']>;
    const saved = { maxFiles: git.maxFiles, maxBytes: git.maxBytes };
    try {
      delete git.maxFiles;
      await expect(
        firstLoad(job({ sourceId: 'cve-list', url: ARCHIVE }), fakeCtx(fakeApi()).ctx, {
          ...base,
          fetch: serve(() => syntheticArchive(REAL.matching, others)),
        }),
      ).rejects.toThrow('archive has too many files');
    } finally {
      git.maxFiles = saved.maxFiles;
      git.maxBytes = saved.maxBytes;
    }
    const { ctx, logs } = fakeCtx(fakeApi());
    await firstLoad(job({ sourceId: 'cve-list', url: ARCHIVE }), ctx, {
      ...base,
      fetch: serve(() => syntheticArchive(REAL.matching, others)),
    });
    const read = logs.find((l) => l.msg === 'archive read')?.extra as Record<string, number>;
    expect(read.kept).toBe(REAL.matching);
    expect(read.filtered).toBe(others);
    const progress = logs.filter((l) => l.msg === 'archive progress');
    expect(progress).toHaveLength(Math.floor(REAL.matching / 10_000));
    expect(Object.keys(progress[0]?.extra ?? {}).sort()).toEqual(['elapsedMs', 'files']);
    evidence(JSON.stringify({ evidence: 'archive-limits-synthetic', ...REAL, kept: read.kept }));
  }, 300_000);
});

// Opt-in: REAL_ARCHIVE=/path/to/cvelistV5.tar.gz (proof/real-archive-run.txt).
describe.skipIf(!process.env.REAL_ARCHIVE)('the real cvelistV5 archive', () => {
  it('reads every matching file without hitting a cap', async () => {
    const path = process.env.REAL_ARCHIVE as string;
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    const t0 = Date.now();
    const bodyOf = () => Readable.toWeb(createReadStream(path)) as unknown as WebReadableStream<Uint8Array>;
    let peak = 0;
    const timer = setInterval(() => {
      peak = Math.max(peak, process.memoryUsage().rss);
    }, 500);
    try {
      await firstLoad(job({ sourceId: 'cve-list', url: ARCHIVE }), ctx, {
        ...base,
        fetch: serve(bodyOf as () => ReadableStream<Uint8Array>),
      });
    } finally {
      clearInterval(timer);
    }
    const read = logs.find((l) => l.msg === 'archive read')?.extra as Record<string, number>;
    const line = {
      evidence: 'real-archive',
      read,
      peakRssMiB: Math.round(peak / 2 ** 20),
      seconds: Math.round((Date.now() - t0) / 1000),
      logs: logs.map((l) => l.msg).filter((m) => m !== 'archive progress'),
    };
    console.log(JSON.stringify(line));
    evidence(JSON.stringify(line));
    expect(read.kept).toBe(430_969);
  }, 3_600_000);
});
