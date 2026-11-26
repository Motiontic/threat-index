import { gunzipSync, gzipSync } from 'node:zlib';
import { inboxChunkKey, inboxManifestKey } from '@ti/core/inbox';
import type { AdvisoryRecord } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { deterministicUlid } from '../lib/ulid.ts';
import { type FakeApi, fakeApi, fakeCtx, job } from '../test-support.ts';
import { type BackfillCounts, type BackfillState, backfill, STATE_KEY } from './affected-backfill.ts';

const SRC = 'github-advisory-db';
const blocked = (async () => {
  throw new TypeError('blocked');
}) as unknown as typeof fetch;
const day = (d: string) => Date.parse(`${d}T10:00:00Z`);
let clock = day('2026-11-24');
const deps = (extra: object = {}) => ({
  fetch: blocked,
  duckdb: () => null,
  now: () => new Date(clock),
  ...extra,
});
const ulid = (ms: number, seed: string) => deterministicUlid(ms, seed);

const advisory = (n: number, over: Partial<AdvisoryRecord> = {}): AdvisoryRecord => ({
  source: SRC,
  sourceId: `GHSA-aaaa-bbbb-000${n}`,
  vulnKey: `CVE-2026-100${n}`,
  status: 'active',
  modified: '2026-11-20T00:00:00.000Z',
  affected: [{ ecosystem: 'npm', name: `pkg-${n}`, rangeType: 'ECOSYSTEM', introduced: '0', fixed: '1.0.0' }],
  reviewed: true,
  ...over,
});

const putPart = (api: FakeApi, jobId: string, records: object[]) =>
  api.putObject(
    `lake/records/${SRC}/2026/part-${jobId}.ndjson.gz`,
    gzipSync(
      `${records.map((r, n) => JSON.stringify({ source: SRC, job_id: jobId, n, record: JSON.stringify(r) })).join('\n')}\n`,
    ),
    'application/octet-stream',
  );
/** An OSV document for GHSA-aaaa-bbbb-000<n>, fixed in `fixed`, as the collector's receipt holds it. */
const osvDoc = (n: number, fixed: string, modified: string) => ({
  id: `GHSA-aaaa-bbbb-000${n}`,
  modified,
  aliases: [`CVE-2026-100${n}`],
  database_specific: { github_reviewed: true },
  affected: [
    {
      package: { ecosystem: 'npm', name: `pkg-${n}` },
      ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed }] }],
    },
  ],
});
const putReceipt = (api: FakeApi, runId: string, bodies: object[]) =>
  api.putObject(
    `raw/${SRC}/2026/11/22/${runId}-0.ndjson.gz`,
    gzipSync(
      `${[
        { type: 'receipt', source: SRC },
        ...bodies.map((body, i) => ({ type: 'item', id: `x${i}`, body: JSON.stringify(body) })),
      ]
        .map((l) => JSON.stringify(l))
        .join('\n')}\n`,
    ),
    'application/gzip',
  );

const OLD_PART = ulid(day('2026-11-10'), 'old');
const NEW_PART = ulid(day('2026-11-18'), 'new');
const RECEIPT = ulid(day('2026-11-22'), 'run');

function seeded(): FakeApi {
  const api = fakeApi();
  const { affected: _a, reviewed: _r, ...oldFormat } = advisory(1);
  void putPart(api, OLD_PART, [
    { ...oldFormat, affected: [{ ecosystem: 'npm', name: 'pkg-1', fixed: '0.9' }] },
  ]);
  void putPart(
    api,
    NEW_PART,
    [1, 2, 3, 4, 5].map((n) => advisory(n)),
  );
  void putReceipt(api, RECEIPT, [osvDoc(3, '3.3.3', '2026-11-22T00:00:00.000Z')]);
  return api;
}

const state = (api: FakeApi) =>
  JSON.parse(new TextDecoder().decode(api.store.get(STATE_KEY))) as BackfillState;
const manifest = (api: FakeApi, id: string) =>
  JSON.parse(new TextDecoder().decode(api.store.get(inboxManifestKey(id)))) as {
    chunks: { key: string; rows: number }[];
  };
const chunkRows = (api: FakeApi, id: string, n: number) =>
  gunzipSync(api.store.get(inboxChunkKey(id, n)) as Uint8Array)
    .toString()
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as { table: string; op: string; row: Record<string, unknown> });
const limits = (cap: number, ms = 40 * 60 * 1000) => ({ dailyWriteCap: cap, runBudgetMs: ms });
const J = (n: number) => `01J0000000000000000000000${n}`;

async function dryRun(api: FakeApi) {
  const { ctx } = fakeCtx(api);
  await backfill(job({ id: J(0), kind: 'affected-backfill' }), ctx, deps(), limits(12));
}
async function writeRun(api: FakeApi, n: number, cap = 12, extra: object = {}) {
  const { ctx, logs } = fakeCtx(api);
  await backfill(job({ id: J(n), kind: 'affected-backfill' }), ctx, deps(extra), limits(cap));
  return logs;
}

describe('affected-backfill', () => {
  it('fails when 1.1.1.1 answers', async () => {
    const api = seeded();
    const { ctx } = fakeCtx(api);
    const reached = (async (url: unknown) => {
      expect(String(url)).toBe('https://1.1.1.1/');
      return new Response('hello');
    }) as unknown as typeof fetch;
    await expect(
      backfill(job({ id: J(0), kind: 'affected-backfill' }), ctx, deps({ fetch: reached })),
    ).rejects.toThrow('affected-backfill: egress not restricted');
    expect(api.store.has(STATE_KEY)).toBe(false);
  });

  it('the first run is a dry run: counts, an empty manifest, countedBy, no rows', async () => {
    clock = day('2026-11-24');
    const api = seeded();
    await dryRun(api);
    expect(manifest(api, J(0)).chunks).toEqual([]);
    const counts = JSON.parse(
      new TextDecoder().decode(api.store.get(`jobs/${J(0)}/counts.json`)),
    ) as BackfillCounts;
    const g = counts.sources[SRC];
    expect(g).toMatchObject({
      copies: 7,
      latest: 5,
      oldFormat: 1,
      parseFailures: 0,
      packageRecords: 5,
      rows: 10,
      writes: 25,
    });
    expect(g?.byEcosystem).toEqual({ npm: { rows: 5, writes: 15 } });
    expect(g?.byRangeType).toEqual({ SEMVER: 0, ECOSYSTEM: 5, EXACT: 0 });
    expect(counts.total).toEqual({ rows: 10, writes: 25, days: 3 });
    expect(counts.dailyWriteCap).toBe(12);
    expect(state(api).countedBy).toBe(J(0));
    expect(state(api).sources[SRC]?.after).toBeNull();
    expect(api.puts.filter((k) => k.startsWith('inbox/') && !k.endsWith('manifest.json'))).toEqual([]);
  });

  it('writes under the cap, whole records per chunk, the newer raw copy, and resumes across days', async () => {
    clock = day('2026-11-24');
    const api = seeded();
    await dryRun(api);
    await writeRun(api, 1);
    let st = state(api);
    expect(st.sources[SRC]).toMatchObject({
      after: 'GHSA-aaaa-bbbb-0002',
      done: false,
      records: 2,
      writes: 10,
    });
    expect(st.writesToday).toBe(10);
    const rows1 = chunkRows(api, J(1), 0);
    expect(rows1.map((r) => r.table)).toEqual([
      'affected',
      'package_advisories',
      'affected',
      'package_advisories',
    ]);

    // Same day: only what is left of the cap (2 units): nothing fits.
    await writeRun(api, 2);
    st = state(api);
    expect(st.writesToday).toBe(10);
    expect(st.sources[SRC]?.after).toBe('GHSA-aaaa-bbbb-0002');
    expect(manifest(api, J(2)).chunks).toEqual([]);

    // Next day resumes after `after`, and uses the raw copy of 0003.
    clock = day('2026-11-25');
    await writeRun(api, 3);
    st = state(api);
    expect(st.sources[SRC]).toMatchObject({ after: 'GHSA-aaaa-bbbb-0004', done: false });
    expect(st.writesToday).toBe(10);
    const rows3 = chunkRows(api, J(3), 0);
    const g3 = rows3.find((r) => r.table === 'affected' && r.row.source_id === 'GHSA-aaaa-bbbb-0003');
    expect(g3?.row.fixed).toBe('3.3.3');
    expect(rows3.map((r) => r.row.source_id)).not.toContain('GHSA-aaaa-bbbb-0002');
  });

  it('never splits a record across chunks, and marks the source done at the end of the walk', async () => {
    clock = day('2026-11-24');
    const api = seeded();
    // 120 packages in one record: 361 rows, 362 with the advisory. Plus a small one after it.
    const big = advisory(9, {
      sourceId: 'GHSA-aaaa-bbbb-0000',
      affected: Array.from({ length: 200 }, (_, i) => ({
        ecosystem: 'npm',
        name: `big-${i}`,
        rangeType: 'ECOSYSTEM' as const,
        fixed: '1.0.0',
      })),
    });
    void putPart(api, ulid(day('2026-11-19'), 'big'), [
      big,
      { ...big, sourceId: 'GHSA-aaaa-bbbb-0001x' },
      { ...big, sourceId: 'GHSA-aaaa-bbbb-0002x' },
      advisory(1),
    ]);
    await dryRun(api);
    await writeRun(api, 1, 10_000);
    const m = manifest(api, J(1));
    expect(m.chunks.length).toBeGreaterThan(1);
    for (let n = 0; n < m.chunks.length; n++) {
      const rows = chunkRows(api, J(1), n);
      expect(rows.length).toBeLessThanOrEqual(500);
      // A chunk ends with a package_advisories row: no record's rows were cut.
      expect(rows.at(-1)?.table).toBe('package_advisories');
      expect(rows[0]?.table).toBe('affected');
    }
    expect(state(api).sources[SRC]).toMatchObject({ done: true });
    expect(state(api).sources[SRC]?.completedAt).toBe(new Date(clock).toISOString());
  });

  it("re-opens a done source when a newer lake part appears and writes only that part's records", async () => {
    clock = day('2026-11-24');
    const api = seeded();
    await dryRun(api);
    await writeRun(api, 1, 10_000);
    expect(state(api).sources[SRC]?.done).toBe(true);
    // Nothing new: a run writes nothing.
    await writeRun(api, 2, 10_000);
    expect(manifest(api, J(2)).chunks).toEqual([]);
    // A newer part, with one changed record.
    clock = day('2026-11-26');
    const newer = ulid(day('2026-11-25'), 'later');
    await putPart(api, newer, [
      advisory(2, {
        modified: '2026-11-25T00:00:00.000Z',
        affected: [{ ecosystem: 'npm', name: 'pkg-2', rangeType: 'ECOSYSTEM', fixed: '2.2.2' }],
      }),
    ]);
    await writeRun(api, 3, 10_000);
    const rows = chunkRows(api, J(3), 0);
    expect(new Set(rows.map((r) => r.row.source_id))).toEqual(new Set(['GHSA-aaaa-bbbb-0002']));
    expect(rows.find((r) => r.table === 'affected')?.row.fixed).toBe('2.2.2');
    expect(state(api).sources[SRC]?.done).toBe(true);
  });

  it('fails on a malformed state', async () => {
    const api = seeded();
    await api.putObject(STATE_KEY, JSON.stringify({ v: 1, countedBy: 5 }), 'application/json');
    const { ctx } = fakeCtx(api);
    await expect(
      backfill(job({ id: J(1), kind: 'affected-backfill' }), ctx, deps(), limits(12)),
    ).rejects.toThrow(/malformed state/);
    await api.putObject(STATE_KEY, 'nope', 'application/json');
    await expect(
      backfill(job({ id: J(1), kind: 'affected-backfill' }), ctx, deps(), limits(12)),
    ).rejects.toThrow(/malformed state/);
  });

  it('stops at the time budget and saves its place', async () => {
    clock = day('2026-11-24');
    const api = seeded();
    await dryRun(api);
    let t = day('2026-11-24');
    const ticking = () => {
      t += 1000;
      return new Date(t);
    };
    const { ctx } = fakeCtx(api);
    await backfill(
      job({ id: J(1), kind: 'affected-backfill' }),
      ctx,
      { fetch: blocked, duckdb: () => null, now: ticking },
      limits(10_000, 3500),
    );
    const s = state(api).sources[SRC];
    expect(s?.done).toBe(false);
    expect(s?.after).not.toBeNull();
    expect(s?.records).toBeLessThan(5);
  });
});
