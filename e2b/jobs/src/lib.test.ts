import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { inboxChunkKey, inboxManifestKey } from '@ti/core/inbox';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { download, USER_AGENT } from './lib/download.ts';
import { writeInbox } from './lib/inbox.ts';
import { type ExecFile, lakeObjectKey, readLakePart, writeLakePart } from './lib/lake.ts';
import { deterministicUlid, newUlid } from './lib/ulid.ts';
import { fakeApi, gz, JOB_ID, noSleep } from './test-support.ts';

const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

describe('ulid', () => {
  it('newUlid is 26 Crockford characters and sorts by time', () => {
    const a = newUlid(1_700_000_000_000);
    const b = newUlid(1_700_000_001_000);
    expect(a).toMatch(ULID);
    expect(a < b).toBe(true);
    expect(newUlid(5)).not.toBe(newUlid(5));
  });
  it('deterministicUlid is stable for a seed and differs between seeds', () => {
    const t = Date.parse('2026-11-22T00:00:00Z');
    const a = deterministicUlid(t, 'epss_band:CVE-2024-1:2026-11-22');
    expect(a).toMatch(ULID);
    expect(a).toBe(deterministicUlid(t, 'epss_band:CVE-2024-1:2026-11-22'));
    expect(a).not.toBe(deterministicUlid(t, 'epss_band:CVE-2024-2:2026-11-22'));
    expect(a.slice(0, 10)).toBe(deterministicUlid(t, 'other').slice(0, 10));
  });
});

describe('download', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'dl-test-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  const fetchSeq = (...responses: (() => Response | Error)[]) => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const fn = (async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      const next = responses.shift();
      if (!next) throw new Error('no more responses');
      const r = next();
      if (r instanceof Error) throw r;
      return r;
    }) as unknown as typeof fetch;
    return { fn, calls };
  };

  it('refuses a URL that is not https', async () => {
    await expect(download('http://example.com/a', join(dir, 'x'), { fetch: fetchSeq().fn })).rejects.toThrow(
      /https/,
    );
  });
  it('follows redirects, sends the User-Agent, and gunzips a .gz path', async () => {
    const { fn, calls } = fetchSeq(
      () => new Response(null, { status: 302, headers: { location: '/real/file.csv.gz' } }),
      () => new Response(gz('a,b\n1,2\n'), { headers: { 'content-type': 'application/gzip' } }),
    );
    const got = await download('https://example.com/start.csv.gz', join(dir, 'out'), { fetch: fn });
    expect(await readFile(join(dir, 'out'), 'utf8')).toBe('a,b\n1,2\n');
    expect(got.bytes).toBe(8);
    expect(calls[1]?.url).toBe('https://example.com/real/file.csv.gz');
    expect(((calls[0]?.init?.headers ?? {}) as Record<string, string>)['user-agent']).toBe(USER_AGENT);
  });
  it('refuses a redirect to http and more than five redirects', async () => {
    const toHttp = fetchSeq(
      () => new Response(null, { status: 301, headers: { location: 'http://evil.test/x' } }),
    );
    await expect(download('https://example.com/a', join(dir, 'x'), { fetch: toHttp.fn })).rejects.toThrow(
      /https/,
    );
    const loop = fetchSeq(
      ...Array.from(
        { length: 7 },
        () => () => new Response(null, { status: 302, headers: { location: '/again' } }),
      ),
    );
    await expect(download('https://example.com/a', join(dir, 'x'), { fetch: loop.fn })).rejects.toThrow(
      /redirects/,
    );
  });
  it('caps the size', async () => {
    const { fn } = fetchSeq(() => new Response('0123456789'));
    await expect(
      download('https://example.com/a', join(dir, 'x'), { fetch: fn, maxBytes: 5 }),
    ).rejects.toThrow(/size limit/);
  });
  it('retries a 503 and a network error, then gives up without the URL in the message', async () => {
    const ok = fetchSeq(
      () => new Response(null, { status: 503 }),
      () => new TypeError('boom'),
      () => new Response('fine'),
    );
    await download('https://example.com/a', join(dir, 'x'), { fetch: ok.fn, sleep: noSleep });
    expect(await readFile(join(dir, 'x'), 'utf8')).toBe('fine');
    const bad = fetchSeq(...Array.from({ length: 4 }, () => () => new Response(null, { status: 500 })));
    const err = await download('https://example.com/secret-path', join(dir, 'y'), {
      fetch: bad.fn,
      sleep: noSleep,
    }).catch((e) => e as Error);
    expect((err as Error).message).toBe('download failed after retries: status 500');
  });
});

describe('lake', () => {
  const rows = [
    { a: 'x', n: 1 },
    { a: 'y', n: 2 },
  ];
  const cols = { a: 'VARCHAR', n: 'BIGINT' } as const;

  it('lakeObjectKey is the lake key, or the same key as ndjson.gz', () => {
    expect(lakeObjectKey('epss', 'epss', 2026, '2026-11-22', 'parquet')).toBe(
      'lake/epss/epss/2026/part-2026-11-22.parquet',
    );
    expect(lakeObjectKey('epss', 'epss', 2026, '2026-11-22', 'ndjson.gz')).toBe(
      'lake/epss/epss/2026/part-2026-11-22.ndjson.gz',
    );
  });
  it('without duckdb it writes gzipped NDJSON that reads back', async () => {
    const deps = { jobId: JOB_ID, duckdb: () => null };
    const part = await writeLakePart(rows, cols, deps);
    expect(part.format).toBe('ndjson.gz');
    expect(gunzipSync(part.bytes).toString('utf8')).toBe('{"a":"x","n":1}\n{"a":"y","n":2}\n');
    expect(await readLakePart(part.bytes, part.format, deps)).toEqual(rows);
  });
  it('with duckdb it runs COPY … parquet with an empty environment and no data-derived names', async () => {
    const calls: { file: string; args: string[]; env: Record<string, string> }[] = [];
    const exec: ExecFile = async (file, args, opts) => {
      calls.push({ file, args, env: opts.env });
      const out = /TO '([^']+)'/.exec(args[1] as string)?.[1];
      if (out) await writeFile(out, 'PARQUET-BYTES');
      return '';
    };
    const secretRows = [{ a: 'secret-value-; DROP', n: 1 }];
    const part = await writeLakePart(secretRows, cols, {
      jobId: JOB_ID,
      duckdb: () => '/usr/local/bin/duckdb',
      execFile: exec,
    });
    expect(part.format).toBe('parquet');
    expect(new TextDecoder().decode(part.bytes)).toBe('PARQUET-BYTES');
    const call = calls[0];
    expect(call?.file).toBe('/usr/local/bin/duckdb');
    expect(call?.env).toEqual({});
    const sql = call?.args[1] as string;
    expect(sql).toContain("read_json('");
    expect(sql).toContain("format='newline_delimited'");
    expect(sql).toContain("columns={'a': 'VARCHAR', 'n': 'BIGINT'}");
    expect(sql).toContain('(FORMAT parquet, COMPRESSION zstd)');
    expect(sql).not.toContain('secret-value');
    expect(sql).toContain(`lake-${JOB_ID}-`);
  });
  it('refuses a column name that is not a plain identifier', async () => {
    await expect(
      writeLakePart([], { 'a; DROP': 'VARCHAR' }, { jobId: JOB_ID, duckdb: () => null }),
    ).rejects.toThrow(/column/);
  });
});

describe('writeInbox', () => {
  it('writes chunks of at most 500 rows, then the manifest last', async () => {
    const api = fakeApi();
    const rows = Array.from({ length: 1100 }, (_, i) => ({
      table: 'changes',
      op: 'upsert' as const,
      row: { id: String(i) },
    }));
    const { chunks } = await writeInbox(api, JOB_ID, rows, () => new Date('2026-11-22T00:00:00Z'));
    expect(chunks).toBe(3);
    expect(api.puts).toEqual([
      inboxChunkKey(JOB_ID, 0),
      inboxChunkKey(JOB_ID, 1),
      inboxChunkKey(JOB_ID, 2),
      inboxManifestKey(JOB_ID),
    ]);
    const counts = [0, 1, 2].map(
      (n) =>
        gunzipSync(api.store.get(inboxChunkKey(JOB_ID, n)) as Uint8Array)
          .toString()
          .trim()
          .split('\n').length,
    );
    expect(counts).toEqual([500, 500, 100]);
    const manifest = JSON.parse(new TextDecoder().decode(api.store.get(inboxManifestKey(JOB_ID)))) as {
      chunks: { rows: number }[];
    };
    expect(manifest.chunks.map((c) => c.rows)).toEqual([500, 500, 100]);
  });
  it('writes an empty manifest when there are no rows', async () => {
    const api = fakeApi();
    await writeInbox(api, JOB_ID, []);
    expect(api.puts).toEqual([inboxManifestKey(JOB_ID)]);
    expect(JSON.parse(new TextDecoder().decode(api.store.get(inboxManifestKey(JOB_ID)))).chunks).toEqual([]);
  });
});
