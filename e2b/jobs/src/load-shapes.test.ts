import { appendFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { inboxChunkKey, inboxManifestKey } from '@ti/core/inbox';
import { lookupVulnKey } from '@ti/core/r2-keys';
import { LANGUAGE_ECOSYSTEMS } from '@ti/parsers/osv';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import cisaKev from '../../../fixtures/cisa-kev/sample.json';
import { fixture } from '../../../test/fixtures';
import { run as bigFile } from './jobs/big-file.ts';
import { run as firstLoad, inputShape, sandboxLinkDeps } from './jobs/first-load.ts';
import { applyCap, cmpLines, MAX_LIST_DOCS, readChangeList } from './lib/changelist.ts';
import { fakeApi, fakeCtx, JOB_ID, job, makeTar, noSleep, paxRecord } from './test-support.ts';

/** Writes a counts line to $EVIDENCE_FILE when set (the loop saves it under proof/). */
const evidence = (line: string) => {
  if (process.env.EVIDENCE_FILE) appendFileSync(process.env.EVIDENCE_FILE, `${line}\n`);
};
const NOW = new Date('2026-11-23T10:00:00Z');
const base = { duckdb: () => null, sleep: noSleep, now: () => NOW };
const lines = (b: Uint8Array | undefined) =>
  gunzipSync(b as Uint8Array)
    .toString()
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));
const source = (id: string) => SOURCE_BY_ID.get(id) as NonNullable<ReturnType<typeof SOURCE_BY_ID.get>>;

const RH_LIST = 'https://security.access.redhat.com/data/csaf/v2/vex/changes.csv';
const RH_ITEM = 'https://security.access.redhat.com/data/csaf/v2/vex/';
const csaf = fixture('red-hat', 'cve-2023-38545.json');
const changes = fixture('red-hat', 'changes.csv');
const refs = changes
  .trim()
  .split('\n')
  .map((l) => l.split(',')[0]?.replaceAll('"', '') as string);

interface Served {
  fetch: typeof fetch;
  calls: string[];
  peak: () => number;
}
/** A fetch that serves the list and the CSAF item for every ref, with per-URL overrides. */
function redHatFetch(over: Record<string, () => Response> = {}, listText = changes): Served {
  const calls: string[] = [];
  let live = 0;
  let peak = 0;
  const fn = (async (input: RequestInfo | URL) => {
    const url = String(input);
    calls.push(url);
    live++;
    peak = Math.max(peak, live);
    try {
      await new Promise<void>((r) => setTimeout(r, 2));
      if (over[url]) return over[url]();
      if (url === RH_LIST) return new Response(listText, { headers: { 'content-type': 'text/csv' } });
      if (url.startsWith(RH_ITEM))
        return new Response(csaf, { headers: { 'content-type': 'application/json' } });
      throw new Error(`unexpected fetch: ${url}`);
    } finally {
      live--;
    }
  }) as typeof fetch;
  return { fetch: fn, calls, peak: () => peak };
}

const request = (api: ReturnType<typeof fakeApi>, body: unknown) =>
  api.putObject(`jobs/${JOB_ID}/request.json`, JSON.stringify(body), 'application/json');
const pair = (time: string, ref: string) => ({ kind: 'timestamp', value: JSON.stringify([time, ref]) });

describe('inputShape', () => {
  it('picks the shape from the pattern and the URL', () => {
    const rh = source('red-hat');
    expect(inputShape(rh, RH_LIST)).toBe('changelist');
    expect(inputShape(rh, `${RH_ITEM}2023/cve-2023-38545.json`)).toBe('change-item');
    const avid = source('avid');
    const sha = 'a'.repeat(40);
    expect(inputShape(avid, `https://github.com/avidml/avid-db/archive/${sha}.tar.gz`)).toBe('archive');
    expect(inputShape(avid, `https://github.com/avidml/avid-db/archive/${'a'.repeat(39)}.tar.gz`)).toBe(
      'git-file',
    );
    expect(inputShape(avid, `https://github.com/other/repo/archive/${sha}.tar.gz`)).toBe('git-file');
    expect(
      inputShape(avid, `https://raw.githubusercontent.com/avidml/avid-db/${sha}/reports/2022/x.json`),
    ).toBe('git-file');
    expect(inputShape(source('cisa-kev'), 'https://feeds.test/kev.json')).toBe('file');
  });
});

describe('changelist first load', () => {
  it('walks the list, fetches every document, parses each and writes rows (≤ 8 in flight)', async () => {
    // The linker keeps advisories only for hot-set vulns, so seed the one the fixture document names.
    const api = fakeApi({ vulns: [{ key: 'CVE-2023-38545', hot: 1 }] });
    const { ctx, logs } = fakeCtx(api);
    await request(api, { cursor: pair('2026-11-23T22:07:53+00:00', refs[0] as string) });
    const served = redHatFetch();
    await firstLoad(job({ sourceId: 'red-hat', url: RH_LIST }), ctx, { ...base, fetch: served.fetch });

    const itemCalls = served.calls.filter((u) => u !== RH_LIST);
    expect(itemCalls).toHaveLength(refs.length);
    expect(itemCalls).toContain(`${RH_ITEM}2022/cve-2022-23219.json`);
    expect(served.peak()).toBeLessThanOrEqual(8);
    const parsed = logs.find((l) => l.msg === 'parsed')?.extra?.records as number;
    expect(parsed).toBeGreaterThan(0);
    const rows = lines(api.store.get(inboxChunkKey(JOB_ID, 0)));
    const manifest = JSON.parse(new TextDecoder().decode(api.store.get(inboxManifestKey(JOB_ID)))) as {
      chunks: { rows: number }[];
    };
    expect(rows.length).toBeGreaterThan(0);
    expect(manifest.chunks.reduce((n, c) => n + c.rows, 0)).toBe(rows.length);
    expect(api.puts.at(-1)).toBe(inboxManifestKey(JOB_ID));
    const docsLog = logs.find((l) => l.msg === 'documents parsed')?.extra;
    expect(docsLog).toEqual({ documents: refs.length, failed: 0, oversize: 0 });
    const text = JSON.stringify(logs);
    expect(text).not.toContain('security.access.redhat.com');
    // Evidence for the PR: counts.
    evidence(
      JSON.stringify({
        evidence: 'changelist-first-load',
        source: 'red-hat',
        documents: refs.length,
        records: parsed,
        inboxRows: rows.length,
      }),
    );
  });

  it('turns a 404 document into text: null, waits on a 429 and retries', async () => {
    const api = fakeApi();
    const { ctx } = fakeCtx(api);
    await request(api, { cursor: pair('2026-11-23T22:07:53+00:00', refs[0] as string) });
    let throttled = false;
    const slept: number[] = [];
    const served = redHatFetch({
      [`${RH_ITEM}${refs[0]}`]: () => new Response('gone', { status: 404 }),
      [`${RH_ITEM}${refs[1]}`]: () => {
        if (!throttled) {
          throttled = true;
          return new Response('slow down', { status: 429, headers: { 'retry-after': '7' } });
        }
        return new Response(csaf);
      },
    });
    await firstLoad(job({ sourceId: 'red-hat', url: RH_LIST }), ctx, {
      ...base,
      fetch: served.fetch,
      sleep: async (ms) => {
        slept.push(ms);
      },
    });
    expect(slept).toContain(7000);
    expect(served.calls.filter((u) => u === `${RH_ITEM}${refs[1]}`)).toHaveLength(2);
    expect(served.calls.filter((u) => u === `${RH_ITEM}${refs[0]}`)).toHaveLength(1);
  });

  it('fails on another 4xx', async () => {
    const api = fakeApi();
    const { ctx } = fakeCtx(api);
    await request(api, { cursor: pair('2026-11-23T22:07:53+00:00', refs[0] as string) });
    const served = redHatFetch({ [`${RH_ITEM}${refs[2]}`]: () => new Response('no', { status: 403 }) });
    await expect(
      firstLoad(job({ sourceId: 'red-hat', url: RH_LIST }), ctx, { ...base, fetch: served.fetch }),
    ).rejects.toThrow('status 403');
    expect(api.puts).not.toContain(inboxManifestKey(JOB_ID));
  });

  it('skips a throwing document, and fails when every document throws', async () => {
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    await request(api, { cursor: pair('2026-11-23T22:07:53+00:00', refs[0] as string) });
    const served = redHatFetch({ [`${RH_ITEM}${refs[3]}`]: () => new Response('not json at all') });
    await firstLoad(job({ sourceId: 'red-hat', url: RH_LIST }), ctx, { ...base, fetch: served.fetch });
    expect(logs.find((l) => l.msg === 'documents parsed')?.extra).toMatchObject({ failed: 1 });

    const api2 = fakeApi();
    await request(api2, { cursor: pair('2026-11-23T22:07:53+00:00', refs[0] as string) });
    const all = Object.fromEntries(refs.map((r) => [`${RH_ITEM}${r}`, () => new Response('nope')]));
    await expect(
      firstLoad(job({ sourceId: 'red-hat', url: RH_LIST }), fakeCtx(api2).ctx, {
        ...base,
        fetch: redHatFetch(all).fetch,
      }),
    ).rejects.toThrow();
  });

  it('trims a first load to the newest documents and fails an update over the cap', () => {
    const ls = Array.from({ length: 12 }, (_, i) => ({ time: `t${i}`, ref: `r${i}`, ms: i }));
    const first = applyCap(ls, 'first-load', 10);
    expect(first.older).toBe(2);
    expect(first.lines[0]?.ref).toBe('r2');
    expect(first.lines.at(-1)?.ref).toBe('r11');
    const upd = applyCap(ls, 'update', 10);
    expect(upd.lines.map((l) => l.ref)).toEqual(ls.slice(0, 10).map((l) => l.ref));
    expect(upd.reached).toEqual(['t9', 'r9']);
    const fits = applyCap(ls, 'update', 12);
    expect(fits.older).toBe(0);
    expect(fits.reached).toBeUndefined();
    expect(applyCap(ls, 'update', 13).reached).toBeUndefined();
    expect(applyCap(ls, 'first-load', 12).reached).toBeUndefined();
  });

  it('cuts equal-time lines by (ms, ref), so the next window neither repeats nor skips one', () => {
    const t = '2026-11-20T00:00:00Z';
    const ms = Date.parse(t);
    const ls = ['d', 'a', 'c', 'b', 'e'].map((r) => ({ time: t, ref: r, ms })).sort(cmpLines);
    const first = applyCap(ls, 'update', 3);
    expect(first.lines.map((l) => l.ref)).toEqual(['a', 'b', 'c']);
    expect(first.reached).toEqual([t, 'c']);
    const reached = first.reached as [string, string];
    const at = { ref: reached[1], ms: Date.parse(reached[0]) };
    const next = ls.filter((l) => cmpLines(l, at) > 0);
    expect(next.map((l) => l.ref)).toEqual(['d', 'e']);
  });
});

describe('big-file (update)', () => {
  it('starts the window after `from` and stops at the target', async () => {
    const api = fakeApi();
    const { ctx } = fakeCtx(api);
    // The list is newest first. Window: after 22:07:19 (cve-2022-22844) up to 22:07:45 (cve-2022-23218).
    await request(api, {
      cursor: pair('2026-11-23T22:07:45+00:00', '2022/cve-2022-23218.json'),
      from: pair('2026-11-23T22:07:19+00:00', '2022/cve-2022-22844.json'),
    });
    const served = redHatFetch();
    await bigFile(job({ kind: 'big-file', sourceId: 'red-hat', url: RH_LIST }), ctx, {
      ...base,
      fetch: served.fetch,
    });
    const fetched = served.calls.filter((u) => u !== RH_LIST).map((u) => u.slice(RH_ITEM.length));
    expect(fetched.sort()).toEqual(['2022/cve-2022-23181.json', '2022/cve-2022-23218.json']);
    expect(api.puts.at(-1)).toBe(inboxManifestKey(JOB_ID));
  });

  it('commits an empty load when the window holds nothing', async () => {
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    await request(api, {
      cursor: pair('2026-11-23T22:07:53+00:00', '2022/cve-2022-23219.json'),
      from: pair('2026-11-23T22:07:53+00:00', '2022/cve-2022-23219.json'),
    });
    await bigFile(job({ kind: 'big-file', sourceId: 'red-hat', url: RH_LIST }), ctx, {
      ...base,
      fetch: redHatFetch().fetch,
    });
    expect(logs.some((l) => l.msg === 'no records: no lake part')).toBe(true);
    expect(api.puts.filter((k) => !k.endsWith('request.json'))).toEqual([inboxManifestKey(JOB_ID)]);
  });
});

describe('big-file over the cap', () => {
  const LIST_TIME = (i: number) => new Date(Date.UTC(2026, 10, 20) + i * 1000).toISOString();
  const bigList = (n: number) =>
    Array.from(
      { length: n },
      (_, i) => `"2024/cve-2024-${String(i).padStart(6, '0')}.json","${LIST_TIME(i)}"`,
    )
      .reverse()
      .join('\n');
  const gone = (n: number): Record<string, () => Response> =>
    Object.fromEntries(
      Array.from({ length: n }, (_, i) => [
        `${RH_ITEM}2024/cve-2024-${String(i).padStart(6, '0')}.json`,
        () => new Response('', { status: 404 }),
      ]),
    );
  const manifestOf = (api: ReturnType<typeof fakeApi>) =>
    JSON.parse(new TextDecoder().decode(api.store.get(inboxManifestKey(JOB_ID)))) as {
      cursor?: { kind: string; value: string };
    };
  const run = async (n: number) => {
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    await request(api, {
      cursor: pair(LIST_TIME(n), `2024/cve-2024-${String(n - 1).padStart(6, '0')}.json`),
      from: pair('2026-11-19T00:00:00Z', 'x'),
    });
    // One real document keeps the run from failing as "every document failed".
    const over = { ...gone(n), [`${RH_ITEM}2024/cve-2024-000000.json`]: () => new Response(csaf) };
    await bigFile(job({ kind: 'big-file', sourceId: 'red-hat', url: RH_LIST }), ctx, {
      ...base,
      fetch: redHatFetch(over, bigList(n)).fetch,
    });
    return { api, logs };
  };

  it('writes a manifest cursor at the last kept line when it stopped short', async () => {
    const { api, logs } = await run(MAX_LIST_DOCS + 5);
    const reached: [string, string] = [
      LIST_TIME(MAX_LIST_DOCS - 1),
      `2024/cve-2024-${String(MAX_LIST_DOCS - 1).padStart(6, '0')}.json`,
    ];
    expect(manifestOf(api).cursor).toEqual({ kind: 'timestamp', value: JSON.stringify(reached) });
    expect(logs.find((l) => l.msg === 'change list read')?.extra).toMatchObject({
      lines: MAX_LIST_DOCS,
      partial: true,
      reached,
      filtered: 0,
    });
  }, 120_000);

  it('writes no manifest cursor when the whole window was processed', async () => {
    const { api, logs } = await run(20);
    expect(manifestOf(api)).not.toHaveProperty('cursor');
    expect(logs.find((l) => l.msg === 'change list read')?.extra).toMatchObject({ partial: false });
  });
});

describe('readChangeList refPrefixes', () => {
  it('keeps listed ecosystems and counts the rest as filtered, not unreadable', async () => {
    const dir = tmpdir();
    const path = join(dir, `list-${process.pid}-${Date.now()}.csv`);
    const t = '2026-11-20T00:00:00Z';
    writeFileSync(
      path,
      [
        `${t},npm/GHSA-1`,
        `${t},PyPI/PYSEC-1`,
        `${t},GitHub Actions/GHSA-2`,
        `${t},Ubuntu/UBUNTU-CVE-1`,
        `${t},Chainguard/CGA-1`,
        `${t},noslash`,
        'garbage',
      ].join('\n'),
    );
    const cfg = { ...source('osv').pull?.changelist } as NonNullable<
      ReturnType<typeof source>['pull']
    >['changelist'] &
      object;
    for (const mode of ['first-load', 'update']) {
      const from = mode === 'update' ? ['2026-01-01T00:00:00Z', ''] : null;
      const out = await readChangeList(path, cfg, { from: from as [string, string] | null, to: null });
      expect(out.lines.map((l) => l.ref).sort()).toEqual([
        'GitHub Actions/GHSA-2',
        'PyPI/PYSEC-1',
        'npm/GHSA-1',
      ]);
      expect(out.filtered).toBe(3);
      expect(out.unreadable).toBe(1);
    }
  });

  it('osv refPrefixes equal the parser LANGUAGE_ECOSYSTEMS', () => {
    const prefixes = source('osv').pull?.changelist?.refPrefixes ?? [];
    expect(new Set(prefixes)).toEqual(new Set(LANGUAGE_ECOSYSTEMS));
    expect(prefixes).toHaveLength(LANGUAGE_ECOSYSTEMS.size);
    for (const id of ['ubuntu', 'debian', 'red-hat'])
      expect(source(id).pull?.changelist?.refPrefixes).toBeUndefined();
  });
});

describe('change-item', () => {
  const itemUrl = `${RH_ITEM}2023/cve-2023-38545.json`;
  it('takes ref and time from the cursor pair', async () => {
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    await request(api, { cursor: pair('2026-11-23T22:07:53+00:00', '2023/cve-2023-38545.json') });
    await bigFile(job({ kind: 'big-file', sourceId: 'red-hat', url: itemUrl }), ctx, {
      ...base,
      fetch: redHatFetch().fetch,
    });
    expect(logs.find((l) => l.msg === 'documents parsed')?.extra).toMatchObject({ documents: 1 });
    expect(Number(logs.find((l) => l.msg === 'parsed')?.extra?.records)).toBeGreaterThan(0);
  });

  it('fails without a cursor pair', async () => {
    const api = fakeApi();
    await expect(
      bigFile(job({ kind: 'big-file', sourceId: 'red-hat', url: itemUrl }), fakeCtx(api).ctx, {
        ...base,
        fetch: redHatFetch().fetch,
      }),
    ).rejects.toThrow('change-item needs');
  });
});

describe('archive first load', () => {
  const SHA = 'b'.repeat(40);
  const ARCHIVE = `https://github.com/avidml/avid-db/archive/${SHA}.tar.gz`;
  const avidFiles = ['AVID-2022-R0001.json', 'AVID-2023-V028.json', 'AVID-2026-R1714.json'];

  const tarball = (extra: Parameters<typeof makeTar>[0] = []) =>
    gzipSync(
      makeTar([
        { path: `avid-db-${SHA}/`, type: '5' },
        {
          path: `avid-db-${SHA}/reports/2022/${avidFiles[0]}`,
          data: fixture('avid', avidFiles[0] as string),
        },
        {
          path: `avid-db-${SHA}/vulnerabilities/2023/${avidFiles[1]}`,
          data: fixture('avid', avidFiles[1] as string),
        },
        {
          path: `avid-db-${SHA}/reports/2026/${avidFiles[2]}`,
          data: fixture('avid', avidFiles[2] as string),
        },
        { path: `avid-db-${SHA}/README.md`, data: '# not included' },
        { path: `avid-db-${SHA}/reports/2022/exploit.py`, data: 'print(1)' },
        { path: `avid-db-${SHA}/reports/2022/link.json`, type: '2' },
        { path: '../escape/AVID-2022-R0001.json', data: '{}' },
        ...extra,
      ]),
    );

  it('parses only the included data files and logs counts', async () => {
    const before = new Set(readdirSync(tmpdir()));
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    const long = `avid-db-${SHA}/reports/2024/AVID-2024-R0099.json`;
    const bytes = tarball([
      { path: 'PaxHeader', type: 'x', data: paxRecord('path', long) },
      { path: 'short', data: fixture('avid', avidFiles[0] as string) },
      { path: `avid-db-${SHA}/reports/2022/AVID-2022-R9999.json`, data: 'x'.repeat(20) },
    ]);
    const fetchFn = (async (input: RequestInfo | URL) => {
      if (String(input) !== ARCHIVE) throw new Error('unexpected fetch');
      return new Response(bytes as BodyInit, { headers: { 'content-type': 'application/x-gzip' } });
    }) as typeof fetch;
    await firstLoad(job({ sourceId: 'avid', url: ARCHIVE }), ctx, { ...base, fetch: fetchFn });

    const read = logs.find((l) => l.msg === 'archive read')?.extra as Record<string, number>;
    // kept: 3 fixtures + the pax-named copy + the x-filled one (the last fails to parse)
    expect(read.kept).toBe(5);
    expect(read.skipped).toBe(2); // the symlink and the `..` path
    expect(read.filtered).toBeGreaterThanOrEqual(2); // README.md and exploit.py
    const d = logs.find((l) => l.msg === 'documents parsed')?.extra as Record<string, number>;
    expect(d).toMatchObject({ documents: 5, failed: 1 });
    const records = Number(logs.find((l) => l.msg === 'parsed')?.extra?.records);
    expect(records).toBeGreaterThan(0);
    const rows = lines(api.store.get(inboxChunkKey(JOB_ID, 0)));
    expect(rows.length).toBeGreaterThan(0);
    expect(api.puts.at(-1)).toBe(inboxManifestKey(JOB_ID));
    // The archive is streamed: no scratch directory is created for it.
    expect(readdirSync(tmpdir()).filter((n) => !before.has(n) && n.startsWith('job-'))).toEqual([]);
    evidence(
      JSON.stringify({
        evidence: 'archive-first-load',
        source: 'avid',
        documents: d.documents,
        failedToParse: d.failed,
        records,
        inboxRows: rows.length,
      }),
    );
  });

  it('fails the job on a bad header checksum', async () => {
    const bad = gzipSync(
      makeTar([{ path: `avid-db-${SHA}/reports/2022/x.json`, data: '{}', badChecksum: true }]),
    );
    const fetchFn = (async () => new Response(bad as BodyInit)) as typeof fetch;
    await expect(
      firstLoad(job({ sourceId: 'avid', url: ARCHIVE }), fakeCtx(fakeApi()).ctx, { ...base, fetch: fetchFn }),
    ).rejects.toThrow('bad header checksum');
  });

  it('parses one raw file as a git-file', async () => {
    const path = 'reports/2022/AVID-2022-R0001.json';
    const url = `https://raw.githubusercontent.com/avidml/avid-db/${SHA}/${path}`;
    const { ctx, logs } = fakeCtx(fakeApi());
    const fetchFn = (async (input: RequestInfo | URL) => {
      if (String(input) !== url) throw new Error('unexpected fetch');
      return new Response(fixture('avid', avidFiles[0] as string));
    }) as typeof fetch;
    await firstLoad(job({ sourceId: 'avid', url }), ctx, { ...base, fetch: fetchFn });
    expect(Number(logs.find((l) => l.msg === 'parsed')?.extra?.records)).toBeGreaterThan(0);
  });
});

describe('speed', () => {
  /** A fake API that counts calls and records what overlaps. */
  function countingApi() {
    const api = fakeApi({
      vulns: Array.from({ length: 5 }, (_, i) => ({ key: `CVE-2019-${1000 + i}` })),
    });
    const calls: string[] = [];
    let live = 0;
    let peak = 0;
    const delay = () => new Promise<void>((r) => setTimeout(r, 3));
    const wrap =
      <A extends unknown[], R>(name: string, fn: (...a: A) => Promise<R>) =>
      async (...a: A): Promise<R> => {
        calls.push(`${name}:${String(a[0])}`);
        live++;
        peak = Math.max(peak, live);
        try {
          await delay();
          return await fn(...a);
        } finally {
          live--;
        }
      };
    const orig = { ...api };
    api.getObject = wrap('get', orig.getObject);
    api.putObject = wrap('put', orig.putObject);
    api.allRows = async function* (table) {
      calls.push(`rows:${table}`);
      live++;
      peak = Math.max(peak, live);
      await delay();
      live--;
      yield* orig.allRows(table);
    };
    return { api, calls, peak: () => peak };
  }

  it('fetches only the shards the listing shows, and loads the three tables together', async () => {
    const c = countingApi();
    const shardFor = (id: string) => lookupVulnKey(id);
    const hit = 'CVE-2025-3248';
    await c.api.putObject(shardFor(hit), JSON.stringify({ [hit]: { key: hit } }), 'application/json');
    c.calls.length = 0;
    const { ctx } = fakeCtx(c.api);
    const { deps, prime } = sandboxLinkDeps(ctx, () => NOW);
    const rec = (key: string) => ({ key, aliases: [], title: key }) as never;
    await prime([rec(hit), rec('CVE-2031-1'), rec('CVE-2031-2'), rec('CVE-2031-3')]);
    const gets = c.calls.filter((x) => x.startsWith('get:'));
    expect(gets).toEqual([`get:${shardFor(hit)}`]);
    expect(await deps.lookupCold(hit)).toEqual({ key: hit });
    expect(await deps.lookupCold('CVE-2031-1')).toBeNull();
    expect(c.calls.filter((x) => x.startsWith('get:'))).toHaveLength(1); // no GET for an unlisted shard
    await deps.read('vulns', [{ key: 'CVE-2019-1000' }]);
    expect(c.calls.filter((x) => x.startsWith('rows:')).sort()).toEqual([
      'rows:advisories',
      'rows:signals',
      'rows:vulns',
    ]);
  });

  it('uploads chunks together and still writes the manifest last', async () => {
    const entry = cisaKev.vulnerabilities[0] as Record<string, unknown>;
    const catalog = {
      ...cisaKev,
      vulnerabilities: Array.from({ length: 1200 }, (_, i) => ({ ...entry, cveID: `CVE-2025-${2000 + i}` })),
    };
    const c = countingApi();
    const { ctx } = fakeCtx(c.api);
    const fetchFn = (async () =>
      new Response(JSON.stringify(catalog), {
        headers: { 'content-type': 'application/json' },
      })) as typeof fetch;
    await firstLoad(job({ sourceId: 'cisa-kev', url: 'https://feeds.test/kev.json' }), ctx, {
      ...base,
      fetch: fetchFn,
    });
    expect(c.api.puts.at(-1)).toBe(inboxManifestKey(JOB_ID));
    expect(c.peak()).toBeGreaterThan(1);
    expect(c.peak()).toBeLessThanOrEqual(4);
    const chunks = c.api.puts.filter((k) => k.endsWith('.ndjson.gz') && k.startsWith('inbox/'));
    expect(chunks.length).toBeGreaterThan(1);
  });
});

describe('package rows in sandbox loads', () => {
  const PACKAGE_TABLES = ['affected', 'package_advisories'];
  const packageRows = (api: ReturnType<typeof fakeApi>) => {
    const chunk = api.store.get(inboxChunkKey(JOB_ID, 0));
    return chunk ? lines(chunk).filter((r) => PACKAGE_TABLES.includes(r.table)) : [];
  };
  const newAdvisories = (api: ReturnType<typeof fakeApi>) => {
    const chunk = api.store.get(inboxChunkKey(JOB_ID, 0));
    return chunk ? lines(chunk).filter((r) => r.table === 'changes' && r.row.kind === 'new_advisory') : [];
  };
  const SHA = 'c'.repeat(40);
  const GH_ARCHIVE = `https://github.com/github/advisory-database/archive/${SHA}.tar.gz`;
  const ghsa = fixture('github-advisory-db', 'GHSA-9x82-4j54-863h.json');
  const ghsaTar = () =>
    gzipSync(
      makeTar([
        {
          path: `a-${SHA}/advisories/github-reviewed/GHSA-9x82-4j54-863h.json`,
          data: ghsa,
        },
      ]),
    );
  const archiveFetch = (() => async (input: RequestInfo | URL) => {
    if (String(input) !== GH_ARCHIVE) throw new Error('unexpected fetch');
    return new Response(ghsaTar() as BodyInit, { headers: { 'content-type': 'application/x-gzip' } });
  })() as typeof fetch;

  const OSV_LIST = 'https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv';
  const OSV_ITEM = 'https://osv-vulnerabilities.storage.googleapis.com/';
  const goDoc = fixture('osv', 'GO-2026-5006.json');
  const osvFetch =
    (list: string, doc: (ref: string) => string): typeof fetch =>
    async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === OSV_LIST) return new Response(list, { headers: { 'content-type': 'text/csv' } });
      if (url.startsWith(OSV_ITEM))
        return new Response(doc(url.slice(OSV_ITEM.length)), {
          headers: { 'content-type': 'application/json' },
        });
      throw new Error(`unexpected fetch: ${url}`);
    };
  const osvWindow = (api: ReturnType<typeof fakeApi>) =>
    request(api, {
      cursor: pair('2026-11-23T22:00:00Z', 'Go/GO-2026-0001'),
      from: pair('2026-11-01T00:00:00Z', 'Go/GO-2026-0000'),
    });

  it('first-load drops package rows and logs the count', async () => {
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    await firstLoad(job({ sourceId: 'github-advisory-db', url: GH_ARCHIVE }), ctx, {
      ...base,
      fetch: archiveFetch,
    });
    expect(packageRows(api)).toEqual([]);
    expect(newAdvisories(api)).toEqual([]); // dropped with the package rows: history never alerts
    expect(logs.find((l) => l.msg === 'package rows left to the backfill')?.extra).toEqual({
      rows: 3, // affected, package_advisories and the record's new_advisory
      reason: 'first-load',
    });
  });

  it('an archive update drops them', async () => {
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    await bigFile(job({ kind: 'big-file', sourceId: 'github-advisory-db', url: GH_ARCHIVE }), ctx, {
      ...base,
      fetch: archiveFetch,
    });
    expect(packageRows(api)).toEqual([]);
    expect(newAdvisories(api)).toEqual([]); // dropped with the package rows: history never alerts
    expect(logs.find((l) => l.msg === 'package rows left to the backfill')?.extra).toEqual({
      rows: 3, // affected, package_advisories and the record's new_advisory
      reason: 'archive',
    });
  });

  it('a change-list update keeps them', async () => {
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    await osvWindow(api);
    await bigFile(job({ kind: 'big-file', sourceId: 'osv', url: OSV_LIST }), ctx, {
      ...base,
      fetch: osvFetch('2026-11-23T21:00:00Z,Go/GO-2026-5006\n', () => goDoc),
    });
    expect(packageRows(api).map((r) => r.table)).toEqual(['affected', 'package_advisories']);
    expect(newAdvisories(api)).toEqual([]); // a first-load never announces, in any mode
    expect(logs.some((l) => l.msg === 'package rows left to the backfill')).toBe(false);
  });

  it('an update over 200,000 units drops them', async () => {
    const api = fakeApi();
    const { ctx, logs } = fakeCtx(api);
    await osvWindow(api);
    const refs = Array.from({ length: 400 }, (_, i) => `Go/GO-2026-${String(i).padStart(4, '0')}`);
    const list = `${refs.map((r, i) => `2026-11-23T21:${String(i % 60).padStart(2, '0')}:00Z,${r}`).join('\n')}\n`;
    const doc = (ref: string) => {
      const id = ref.slice(3, -5);
      return JSON.stringify({
        id,
        modified: '2026-11-23T20:00:00Z',
        aliases: [`CVE-2026-${id.slice(-4)}`],
        affected: Array.from({ length: 200 }, (_, i) => ({
          package: { ecosystem: 'Go', name: `example.com/${id}/p${i}` },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }],
        })),
      });
    };
    await bigFile(job({ kind: 'big-file', sourceId: 'osv', url: OSV_LIST }), ctx, {
      ...base,
      fetch: osvFetch(list, doc),
    });
    expect(packageRows(api)).toEqual([]);
    const dropped = logs.find((l) => l.msg === 'package rows left to the backfill')?.extra;
    expect(dropped?.reason).toBe('over cap');
    expect(dropped?.rows).toBeGreaterThan(66_000);
  }, 60_000);
});
