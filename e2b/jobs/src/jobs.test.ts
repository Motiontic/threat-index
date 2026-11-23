import { gunzipSync } from 'node:zlib';
import { inboxChunkKey, inboxManifestKey } from '@ti/core/inbox';
import { describe, expect, it } from 'vitest';
import kev from '../../../fixtures/cisa-kev/sample.json';
import { fixture } from '../../../test/fixtures';
import { EPSS_URL, run as epssDiff, parseEpss } from './jobs/epss-diff.ts';
import { run as firstLoad } from './jobs/first-load.ts';
import { foldReceipt, run as nightlyFold } from './jobs/nightly-fold.ts';
import { fakeApi, fakeCtx, fakeFetch, gz, JOB_ID, job, noSleep } from './test-support.ts';

const KEV_URL = 'https://feeds.test/kev.json';
const NOW = new Date('2026-11-23T10:00:00Z');
const noDuckdb = { duckdb: () => null, sleep: noSleep, now: () => NOW };
const text = (b: Uint8Array | undefined) => new TextDecoder().decode(b);
const lines = (b: Uint8Array | undefined) =>
  gunzipSync(b as Uint8Array)
    .toString()
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));

describe('first-load', () => {
  it('downloads KEV, links it, and writes chunks of ≤ 500, a lake part and the manifest last', async () => {
    const entry = kev.vulnerabilities[0] as Record<string, unknown>;
    const catalog = {
      ...kev,
      vulnerabilities: Array.from({ length: 400 }, (_, i) => ({
        ...entry,
        cveID: `CVE-2025-${String(1000 + i)}`,
        knownRansomwareCampaignUse: i % 2 === 0 ? 'Known' : 'Unknown',
      })),
    };
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    const fetchFn = fakeFetch({
      [KEV_URL]: () =>
        new Response(JSON.stringify(catalog), { headers: { 'content-type': 'application/json' } }),
    });
    await firstLoad(job({ sourceId: 'cisa-kev', url: KEV_URL }), ctx, { ...noDuckdb, fetch: fetchFn });

    const chunkKeys = api.puts.filter((k) => k.startsWith('inbox/') && k.endsWith('.ndjson.gz'));
    expect(chunkKeys.length).toBeGreaterThan(1);
    for (const [n, k] of chunkKeys.entries()) {
      expect(k).toBe(inboxChunkKey(JOB_ID, n));
      expect(lines(api.store.get(k)).length).toBeLessThanOrEqual(500);
    }
    expect(api.puts.at(-1)).toBe(inboxManifestKey(JOB_ID));
    const manifest = JSON.parse(text(api.store.get(inboxManifestKey(JOB_ID)))) as {
      chunks: { rows: number }[];
    };
    const tables = new Set(chunkKeys.flatMap((k) => lines(api.store.get(k)).map((r) => r.table)));
    expect(tables).toContain('signals');
    expect(tables).toContain('vulns');
    expect(manifest.chunks.length).toBe(chunkKeys.length);

    const lakeKey = `lake/records/cisa-kev/2026/part-${JOB_ID}.ndjson.gz`;
    expect(api.puts).toContain(lakeKey);
    expect(api.puts.indexOf(lakeKey)).toBeLessThan(api.puts.indexOf(chunkKeys[0] as string));
    const lake = lines(api.store.get(lakeKey));
    expect(lake).toHaveLength(600); // 400 exploited + 200 ransomware signals
    expect(lake[0]).toMatchObject({ source: 'cisa-kev', job_id: JOB_ID, n: 0 });
    expect(typeof lake[0].record).toBe('string');
    expect(logs.some((l) => l.msg === 'lake part written' && l.extra?.format === 'ndjson.gz')).toBe(true);
    // Logs hold counts, never records.
    expect(JSON.stringify(logs)).not.toContain('CVE-2025-');
  });

  it('works on the fixture file and sees rows an earlier batch wrote', async () => {
    const api = fakeApi();
    const { ctx } = fakeCtx(api);
    const fetchFn = fakeFetch({ [KEV_URL]: () => new Response(JSON.stringify(kev)) });
    // `.json` path, no content type: the text is parsed as JSON.
    await firstLoad(job({ sourceId: 'cisa-kev', url: KEV_URL }), ctx, { ...noDuckdb, fetch: fetchFn });
    const rows = lines(api.store.get(inboxChunkKey(JOB_ID, 0)));
    expect(rows.some((r) => r.table === 'signals' && r.row.vuln_key === 'CVE-2025-3248')).toBe(true);
  });

  it('fails on a source with no parser, on no URL, and without a sourceId', async () => {
    const api = fakeApi();
    const { ctx } = fakeCtx(api);
    await expect(firstLoad(job({ sourceId: 'epss', url: KEV_URL }), ctx, noDuckdb)).rejects.toThrow(
      'source epss has no parser',
    );
    await expect(firstLoad(job({ sourceId: 'cisa-kev' }), ctx, noDuckdb)).rejects.toThrow(/no URL/);
    await expect(firstLoad(job(), ctx, noDuckdb)).rejects.toThrow(/sourceId/);
    expect(api.puts).toEqual([]);
  });
});

describe('epss-diff', () => {
  const day = '2026-11-22';
  const hotVulns = (keys: string[]) => keys.map((key) => ({ key, hot: 1 }));
  const epssFetch = () => fakeFetch({ [EPSS_URL]: () => new Response(gz(fixture('epss', 'today.csv'))) });

  async function seedYesterday(api: ReturnType<typeof fakeApi>) {
    const { writeLakePart } = await import('./lib/lake.ts');
    const parsed = parseEpss(fixture('epss', 'yesterday.csv'));
    const part = await writeLakePart(
      parsed.rows as unknown as Record<string, unknown>[],
      {
        cve: 'VARCHAR',
        epss: 'DOUBLE',
        percentile: 'DOUBLE',
        model_version: 'VARCHAR',
        score_date: 'VARCHAR',
      },
      { jobId: JOB_ID, duckdb: () => null },
    );
    await api.putObject(
      'lake/epss/epss/2026/part-2026-11-21.ndjson.gz',
      part.bytes,
      'application/octet-stream',
    );
  }

  it('parses the comment line and the CSV', () => {
    const p = parseEpss(fixture('epss', 'today.csv'));
    expect(p.day).toBe(day);
    expect(p.rows).toHaveLength(10);
    expect(p.bad).toBe(0);
    expect(p.rows[0]).toEqual({
      cve: 'CVE-2024-0001',
      epss: 0.02,
      percentile: 0.6,
      model_version: 'v2025.03.14',
      score_date: '2026-11-22T12:55:00Z',
    });
  });

  it('emits only hot band changes, with stable ids', async () => {
    const runOnce = async () => {
      const api = fakeApi({
        // 0001 0→1, 0002 1→2, 0003 same band, 0004 not hot, 0007 3→2, 0010 gone today, 0011 new today, 0099 in neither.
        vulns: hotVulns([
          'CVE-2024-0001',
          'CVE-2024-0002',
          'CVE-2024-0003',
          'CVE-2024-0007',
          'CVE-2024-0010',
          'CVE-2024-0011',
          'CVE-2024-0099',
        ]).concat([{ key: 'CVE-2024-0004', hot: 0 }]),
      });
      await seedYesterday(api);
      const { ctx, logs } = fakeCtx(api);
      await epssDiff(job({ kind: 'epss-diff', sourceId: 'epss' }), ctx, { ...noDuckdb, fetch: epssFetch() });
      return { api, logs };
    };
    const { api, logs } = await runOnce();
    expect(api.puts).toContain('lake/epss/epss/2026/part-2026-11-22.ndjson.gz');
    expect(api.puts.at(-1)).toBe(inboxManifestKey(JOB_ID));
    const rows = lines(api.store.get(inboxChunkKey(JOB_ID, 0)));
    expect(rows.map((r) => r.row.entity_key)).toEqual(['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0007']);
    expect(rows[0]).toMatchObject({
      table: 'changes',
      op: 'upsert',
      row: { kind: 'epss_band', old: '0.005', new: '0.02', at: '2026-11-22T00:00:00Z', source: 'epss' },
    });
    expect(logs.some((l) => l.msg === 'lake part written' && l.extra?.format === 'ndjson.gz')).toBe(true);
    const again = (await runOnce()).api;
    expect(lines(again.store.get(inboxChunkKey(JOB_ID, 0))).map((r) => r.row.id)).toEqual(
      rows.map((r) => r.row.id),
    );
  });

  it('finds no previous day and writes an empty manifest', async () => {
    const api = fakeApi({ vulns: hotVulns(['CVE-2024-0001']) });
    const { ctx, logs } = fakeCtx(api);
    await epssDiff(job({ kind: 'epss-diff', sourceId: 'epss' }), ctx, { ...noDuckdb, fetch: epssFetch() });
    expect(logs.some((l) => l.msg === 'no previous day')).toBe(true);
    expect(JSON.parse(text(api.store.get(inboxManifestKey(JOB_ID)))).chunks).toEqual([]);
  });

  it('fails when more than 1% of rows are bad, and without sourceId epss', async () => {
    const bad = `${fixture('epss', 'today.csv')}CVE-2024-0100,notanumber,0.1\n`;
    const api = fakeApi();
    const { ctx } = fakeCtx(api);
    const fetchFn = fakeFetch({ [EPSS_URL]: () => new Response(gz(bad)) });
    await expect(
      epssDiff(job({ kind: 'epss-diff', sourceId: 'epss' }), ctx, { ...noDuckdb, fetch: fetchFn }),
    ).rejects.toThrow(/too many bad rows/);
    await expect(epssDiff(job({ kind: 'epss-diff' }), ctx, noDuckdb)).rejects.toThrow(/sourceId/);
    expect(api.puts).toEqual([]);
  });
});

describe('nightly-fold', () => {
  const receipt = (runId: string) =>
    [
      JSON.stringify({
        type: 'receipt',
        source: 'cisa-kev',
        runId,
        step: 0,
        fetchedAt: '2026-11-22T03:00:00Z',
        contentType: 'application/json',
        encoding: 'utf8',
        body: '{"a":1}',
      }),
      JSON.stringify({ type: 'item', id: 'CVE-2025-1', body: { x: 1 } }),
      'this is not json',
    ].join('\n');

  it('folds two receipts into one part per source and skips a bad line', async () => {
    const api = fakeApi();
    await api.putObject(
      'raw/cisa-kev/2026/11/22/01HZX3K9ABCDEFGHJKMNPQRSAA-0.ndjson.gz',
      gz(receipt('01HZX3K9ABCDEFGHJKMNPQRSAA')),
      'application/gzip',
    );
    await api.putObject(
      'raw/cisa-kev/2026/11/22/01HZX3K9ABCDEFGHJKMNPQRSBB-1.ndjson.gz',
      gz(receipt('01HZX3K9ABCDEFGHJKMNPQRSBB')),
      'application/gzip',
    );
    await api.putObject('raw/cisa-kev/2026/11/21/other-0.ndjson.gz', gz(receipt('x')), 'application/gzip');
    const { ctx, logs } = fakeCtx(api);
    await nightlyFold(job({ kind: 'nightly-fold', day: '2026-11-22' }), ctx, noDuckdb);

    const key = 'lake/raw/cisa-kev/2026/part-2026-11-22.ndjson.gz';
    const rows = lines(api.store.get(key));
    expect(rows).toHaveLength(4);
    expect(rows[0]).toMatchObject({
      source: 'cisa-kev',
      run_id: '01HZX3K9ABCDEFGHJKMNPQRSAA',
      step: 0,
      type: 'receipt',
      item_id: null,
      encoding: 'utf8',
    });
    expect(rows[1]).toMatchObject({
      type: 'item',
      item_id: 'CVE-2025-1',
      fetched_at: '2026-11-22T03:00:00Z',
      content_type: 'application/json',
      body: '{"x":1}',
    });
    expect(rows[2]).toMatchObject({ run_id: '01HZX3K9ABCDEFGHJKMNPQRSBB', step: 1 });
    expect(api.puts.filter((k) => k.startsWith('lake/'))).toEqual([key]);
    expect(api.puts.at(-1)).toBe(inboxManifestKey(JOB_ID));
    expect(logs.find((l) => l.msg === 'fold done')?.extra).toMatchObject({
      day: '2026-11-22',
      parts: 1,
      rows: 4,
      bad: 2,
    });
  });

  it('defaults to yesterday (UTC) and a rerun overwrites the part', async () => {
    const api = fakeApi();
    await api.putObject(
      'raw/cisa-kev/2026/11/22/01HZX3K9ABCDEFGHJKMNPQRSAA-0.ndjson.gz',
      gz(receipt('01HZX3K9ABCDEFGHJKMNPQRSAA')),
      'application/gzip',
    );
    const { ctx } = fakeCtx(api);
    await nightlyFold(job({ kind: 'nightly-fold' }), ctx, noDuckdb);
    await nightlyFold(job({ kind: 'nightly-fold' }), ctx, noDuckdb);
    const parts = api.puts.filter((k) => k.startsWith('lake/'));
    expect(parts).toEqual(Array(2).fill('lake/raw/cisa-kev/2026/part-2026-11-22.ndjson.gz'));
    expect(api.store.size).toBe(1 + 1 + 1); // receipt, part, manifest
  });

  it('foldReceipt rejects a file name it cannot read', () => {
    expect(foldReceipt('s', 'weird.ndjson.gz', '{}')).toEqual({ rows: [], bad: 1 });
  });
});
