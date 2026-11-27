import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { parseKev } from '@ti/parsers/kev';
import { describe, expect, it } from 'vitest';
import type { DeepQuery } from '../../../../apps/api/src/lib/deep-templates.ts';
import { deepRows } from '../../../../apps/mcp/src/tools/deep-format.ts';
import { fakeApi, fakeCtx, gz, job } from '../test-support.ts';
import type { JobDeps } from '../types.ts';
import { buildSql, finish, MAX_SCAN_OBJECTS, matches, planScan, run } from './deep-query.ts';

const NOW = new Date('2026-11-23T10:00:00Z');
const at = (p: string) => new URL(`../../../../${p}`, import.meta.url);
const lakeRow = (source: string, jobId: string, n: number, record: unknown) => ({
  source,
  job_id: jobId,
  n,
  record: JSON.stringify(record),
});
const nd = (rows: unknown[]) => gz(`${rows.map((r) => JSON.stringify(r)).join('\n')}\n`);
const q = (template: DeepQuery['template'], params: Record<string, string>): DeepQuery => ({
  template,
  params,
});

describe('buildSql', () => {
  const files = ['p-0.ndjson.gz', 'p-1.parquet'];
  const sets: Record<string, Record<string, string>[]> = {
    'cve-history': [{ cve: 'CVE-2024-1111' }, { cve: 'CVE-2099-9999' }],
    'package-advisories': [
      { ecosystem: 'PyPI', package: 'zzzpkg' },
      { ecosystem: 'npm', package: '@a/qqqpkg' },
    ],
    'company-breaches': [{ company: 'Acme Widgets' }, { company: 'domain:zzz.example.org' }],
    'kev-additions': [
      { from: '2025-01-01', to: '2025-02-02' },
      { from: '2024-03-03', to: '2024-04-04' },
    ],
    'epss-history': [
      { cve: 'CVE-2024-1111', from: '2026-11-01', to: '2026-11-22' },
      { cve: 'CVE-2024-2222', from: '2026-10-01', to: '2026-10-05' },
    ],
  };
  for (const [template, list] of Object.entries(sets)) {
    it(`${template}: no param value in the SQL, and one SQL for any params`, () => {
      const [a, b] = list.map(() => buildSql(template as DeepQuery['template'], files, '/tmp/x')) as [
        string,
        string,
      ];
      expect(a).toBe(b);
      for (const params of list) for (const v of Object.values(params)) expect(a).not.toContain(v);
      expect(a).toContain('LIMIT 5000');
      expect(a).toContain('params.json');
    });
  }
  it('reads params as explicit VARCHAR columns and compares KEV day prefixes', () => {
    const sql = buildSql('kev-additions', ['p-0.ndjson.gz'], '/d');
    expect(sql).toContain(`read_json('/d/params.json', columns={'cve': 'VARCHAR'`);
    expect(sql).toContain(`'from': 'VARCHAR', 'to': 'VARCHAR'}`);
    expect(sql).toContain(`substr(json_extract_string(record, '$.firstSeen'), 1, 10) BETWEEN`);
  });
  it('turns off extension autoinstall and autoload before anything is read', () => {
    const sql = buildSql('kev-additions', ['p-0.ndjson.gz'], '/d');
    expect(
      sql.startsWith('SET autoinstall_known_extensions=false;\nSET autoload_known_extensions=false;'),
    ).toBe(true);
  });
  it('names only generated files', () => {
    const sql = buildSql('kev-additions', ['p-0.ndjson.gz'], "/tmp/a'b");
    expect(sql).toContain("/tmp/a''b/p-0.ndjson.gz");
    expect(sql).not.toContain('union_by_name');
    expect(buildSql('cve-history', ['p-1.parquet'], '/d')).toContain('union_by_name=true');
  });
});

describe('planScan', () => {
  const o = (key: string, size = 10) => ({ key, size });
  it('cve-history reads ingestible sources only, parquet and ndjson.gz only', () => {
    const plan = planScan(q('cve-history', { cve: 'CVE-2024-1111' }), [
      o('lake/records/nvd/2026/part-A.parquet'),
      o('lake/records/nvd/2026/part-B.ndjson.gz'),
      o('lake/records/nvd/2026/part-C.txt'),
      o('lake/records/not-a-source/2026/part-D.parquet'),
      o('lake/epss/epss/2026/part-2026-11-01.parquet'),
      o('raw/nvd/x.ndjson.gz'),
    ]);
    expect(plan.map((p) => p.key)).toEqual([
      'lake/records/nvd/2026/part-A.parquet',
      'lake/records/nvd/2026/part-B.ndjson.gz',
    ]);
  });
  it('skips link and wait sources', async () => {
    const { SOURCES } = await import('@ti/sources/registry');
    for (const licence of ['link', 'wait'] as const) {
      const s = SOURCES.find((x) => x.licence === licence);
      if (!s) continue;
      expect(
        planScan(q('cve-history', { cve: 'CVE-2024-1111' }), [o(`lake/records/${s.id}/2026/part-A.parquet`)]),
      ).toEqual([]);
    }
  });
  it('kev-additions reads cisa-kev only', () => {
    const plan = planScan(q('kev-additions', { from: '2025-01-01', to: '2025-12-31' }), [
      o('lake/records/cisa-kev/2025/part-A.ndjson.gz'),
      o('lake/records/nvd/2025/part-A.ndjson.gz'),
    ]);
    expect(plan).toHaveLength(1);
  });
  it('epss-history keeps day parts in range and years in range', () => {
    const plan = planScan(q('epss-history', { cve: 'CVE-2024-1111', from: '2025-12-30', to: '2026-01-02' }), [
      o('lake/epss/epss/2025/part-2025-12-29.parquet'),
      o('lake/epss/epss/2025/part-2025-12-31.parquet'),
      o('lake/epss/epss/2026/part-2026-01-02.ndjson.gz'),
      o('lake/epss/epss/2026/part-2026-01-03.ndjson.gz'),
      o('lake/epss/epss/2026/other.parquet'),
    ]);
    expect(plan.map((p) => p.key)).toEqual([
      'lake/epss/epss/2025/part-2025-12-31.parquet',
      'lake/epss/epss/2026/part-2026-01-02.ndjson.gz',
    ]);
  });
  it('fails scan_too_large on too many objects or bytes', () => {
    const many = Array.from({ length: MAX_SCAN_OBJECTS + 1 }, (_, i) =>
      o(`lake/records/cisa-kev/2025/part-${i}.parquet`),
    );
    const kev = q('kev-additions', { from: '2025-01-01', to: '2025-02-01' });
    expect(() => planScan(kev, many)).toThrow('deep-query: scan_too_large');
    expect(() => planScan(kev, [o('lake/records/cisa-kev/2025/part-A.parquet', 600 * 1024 * 1024)])).toThrow(
      'deep-query: scan_too_large',
    );
  });
});

describe('matches', () => {
  it('cve-history by key, vulnKey or alias', () => {
    const query = q('cve-history', { cve: 'CVE-2024-1111' });
    expect(matches(query, { key: 'cve-2024-1111' })).toBe(true);
    expect(matches(query, { vulnKey: 'CVE-2024-1111' })).toBe(true);
    expect(matches(query, { key: 'GHSA-x', aliases: ['CVE-2024-1111'] })).toBe(true);
    expect(matches(query, { key: 'GHSA-x', title: 'mentions CVE-2024-1111' })).toBe(false);
  });
  it('package-advisories needs ecosystem (any case) and exact name', () => {
    const query = q('package-advisories', { ecosystem: 'pypi', package: 'Foo' });
    const adv = (eco: string, name: string) => ({ sourceId: 'X', affected: [{ ecosystem: eco, name }] });
    expect(matches(query, adv('PyPI', 'Foo'))).toBe(true);
    expect(matches(query, adv('PyPI', 'foo'))).toBe(false);
    expect(matches(query, adv('npm', 'Foo'))).toBe(false);
    expect(matches(query, { key: 'CVE-1' })).toBe(false);
  });
  it('company-breaches by key or name', () => {
    const n = { noticeId: '1', rawName: 'Acme Widgets Inc', companyKey: 'cik:5' };
    expect(matches(q('company-breaches', { company: 'cik:5' }), n)).toBe(true);
    expect(matches(q('company-breaches', { company: 'cik:6' }), n)).toBe(false);
    expect(matches(q('company-breaches', { company: 'widgets' }), n)).toBe(true);
    expect(matches(q('company-breaches', { company: 'domain:acme.com' }), n)).toBe(false);
  });
});

describe('finish', () => {
  const kev = q('kev-additions', { from: '2025-01-01', to: '2025-12-31' });
  const sig = {
    vulnKey: 'CVE-2025-1',
    kind: 'exploited_wild',
    source: 'cisa-kev',
    ref: 'CVE-2025-1',
    firstSeen: '2025-05-05',
  };
  it('drops duplicates, keeps the newest job per identity, caps and truncates', () => {
    const rows = [
      lakeRow('cisa-kev', '01A', 0, sig),
      lakeRow('cisa-kev', '01A', 0, sig),
      lakeRow('cisa-kev', '01B', 0, { ...sig, evidenceDate: '2025-05-05' }),
      lakeRow('cisa-kev', '01A', 1, { ...sig, vulnKey: 'CVE-2025-2', ref: 'CVE-2025-2' }),
      lakeRow('cisa-kev', '01A', 2, {
        ...sig,
        vulnKey: 'CVE-2025-3',
        ref: 'CVE-2025-3',
        firstSeen: '2024-01-01',
      }),
      { source: 'cisa-kev', job_id: '01A', n: 3, record: 'not json' },
    ];
    const f = finish(kev, rows);
    expect(f.rows.map((r) => (r.record as { ref: string }).ref)).toEqual(['CVE-2025-1', 'CVE-2025-2']);
    expect(f.rows[0]?.jobId).toBe('01B');
    expect(f.sources).toEqual(['cisa-kev']);
    expect(finish(kev, rows, 1)).toMatchObject({ truncated: true });
  });
  it('what finish writes is what the MCP tool reads: rows flatten, jobId is dropped', () => {
    const f = finish(kev, [lakeRow('cisa-kev', '01A', 0, sig)]);
    expect(f.rows[0]).toMatchObject({ source: 'cisa-kev', jobId: '01A', record: { ref: 'CVE-2025-1' } });
    const rows = deepRows(f.rows, 'kev-additions');
    expect(rows).toEqual([
      {
        source: 'cisa-kev',
        vuln_key: 'CVE-2025-1',
        kind: 'exploited_wild',
        ref: 'CVE-2025-1',
        first_seen: '2025-05-05',
      },
    ]);
  });
  it('cve-history keeps each distinct version', () => {
    const v = (modified: string) => ({ key: 'CVE-2024-1', modified, source: 'nvd', aliases: [] });
    const f = finish(q('cve-history', { cve: 'CVE-2024-1' }), [
      lakeRow('nvd', '01A', 0, v('2024-01-01')),
      lakeRow('nvd', '01B', 0, v('2024-02-01')),
      lakeRow('nvd', '01C', 0, v('2024-02-01')),
    ]);
    expect(f.rows).toHaveLength(2);
    expect(f.rows.map((r) => (r.record as { modified: string }).modified)).toEqual([
      '2024-01-01',
      '2024-02-01',
    ]);
  });
});

describe('run', () => {
  const request = (template: string, params: Record<string, string>) =>
    JSON.stringify({ kind: 'deep-query', template, params, createdAt: NOW.toISOString() });
  const blocked = (async () => {
    throw new Error('blocked');
  }) as unknown as typeof fetch;
  const deps = (over: Partial<JobDeps> = {}): JobDeps => ({
    now: () => NOW,
    duckdb: () => null,
    fetch: blocked,
    ...over,
  });
  const kevRecords = parseKev(JSON.parse(readFileSync(at('fixtures/cisa-kev/sample.json'), 'utf8'))).records;

  function seeded() {
    const api = fakeApi();
    const part = (jobId: string) => nd(kevRecords.map((r, n) => lakeRow('cisa-kev', jobId, n, r)));
    api.store.set('lake/records/cisa-kev/2026/part-01HZA.ndjson.gz', part('01HZA'));
    api.store.set('lake/records/cisa-kev/2026/part-01HZB.ndjson.gz', part('01HZB'));
    api.store.set(
      'lake/records/nvd/2026/part-01HZA.ndjson.gz',
      nd([
        lakeRow('nvd', '01HZA', 0, {
          key: 'CVE-2025-3248',
          kind: 'cve',
          title: 't',
          modified: '2025-05-06T00:00:00Z',
          source: 'nvd',
          cwe: [],
          aliases: [],
          summary: '',
        }),
        lakeRow('nvd', '01HZA', 1, {
          key: 'CVE-2025-9999',
          kind: 'cve',
          title: 'other',
          modified: '2025-05-06T00:00:00Z',
          source: 'nvd',
          cwe: [],
          aliases: [],
          summary: '',
        }),
      ]),
    );
    api.store.set(
      'lake/records/osv/2026/part-01HZA.ndjson.gz',
      nd([
        lakeRow('osv', '01HZA', 0, {
          source: 'osv',
          sourceId: 'PYSEC-1',
          vulnKey: 'CVE-2025-3248',
          status: 'active',
          modified: '2025-06-01T00:00:00Z',
          affected: [{ ecosystem: 'PyPI', name: 'langflow' }],
        }),
        lakeRow('osv', '01HZA', 1, {
          source: 'osv',
          sourceId: 'PYSEC-2',
          vulnKey: null,
          status: 'active',
          modified: '2025-06-01T00:00:00Z',
          affected: [{ ecosystem: 'npm', name: 'langflow' }],
        }),
      ]),
    );
    api.store.set(
      'lake/records/hhs-ocr/2026/part-01HZA.ndjson.gz',
      nd([
        lakeRow('hhs-ocr', '01HZA', 0, {
          source: 'hhs-ocr',
          noticeId: 'N1',
          rawName: 'Acme Widgets Inc',
          companyKey: 'cik:77',
          countUnit: 'individuals',
        }),
      ]),
    );
    for (const f of ['today', 'yesterday']) {
      const text = readFileSync(at(`fixtures/epss/${f}.csv`), 'utf8').split('\n');
      const date = /score_date:(\d{4}-\d{2}-\d{2})/.exec(text[0] as string)?.[1] as string;
      const rows = text
        .slice(2)
        .filter(Boolean)
        .map((l) => l.split(','))
        .map(([cve, epss, percentile]) => ({
          cve,
          epss: Number(epss),
          percentile: Number(percentile),
          model_version: 'v2025.03.14',
          score_date: `${date}T12:55:00Z`,
        }));
      api.store.set(`lake/epss/epss/2026/part-${date}.ndjson.gz`, nd(rows));
    }
    return api;
  }
  const start = async (
    api: ReturnType<typeof seeded>,
    template: string,
    params: Record<string, string>,
    d = deps(),
  ) => {
    api.store.set(`jobs/${job().id}/request.json`, new TextEncoder().encode(request(template, params)));
    const { ctx, logs } = fakeCtx(api);
    await run(job({ kind: 'deep-query' }), ctx, d);
    const result = JSON.parse(new TextDecoder().decode(api.store.get(`jobs/${job().id}/result.json`)));
    return { result, logs };
  };

  it('kev-additions: dedupes the two KEV copies, writes result.json and an empty manifest', async () => {
    const api = seeded();
    const { result, logs } = await start(api, 'kev-additions', { from: '2025-05-01', to: '2025-05-31' });
    expect(result.rowCount).toBe(1);
    expect(result.rows[0].record.vulnKey).toBe('CVE-2025-3248');
    expect(result.rows[0].jobId).toBe('01HZB');
    expect(result).toMatchObject({ template: 'kev-additions', truncated: false, sources: ['cisa-kev'] });
    expect(result.scanned.objects).toBe(2);
    expect(api.types.get(`jobs/${job().id}/result.json`)).toBe('application/json');
    const manifest = JSON.parse(new TextDecoder().decode(api.store.get(`inbox/${job().id}/manifest.json`)));
    expect(manifest.chunks).toEqual([]);
    const done = logs.find((l) => l.msg === 'deep query done')?.extra;
    expect(done).toMatchObject({ objects: 2, rows: 1 });
    expect(JSON.stringify(logs)).not.toContain('CVE-2025-3248');
  });
  it('kev-additions out of range is empty', async () => {
    const { result } = await start(seeded(), 'kev-additions', { from: '2024-01-01', to: '2024-02-01' });
    expect(result.rows).toEqual([]);
  });
  it('cve-history finds every source', async () => {
    const { result } = await start(seeded(), 'cve-history', { cve: 'CVE-2025-3248' });
    expect(result.rows.map((r: { source: string }) => r.source)).toEqual(['cisa-kev', 'nvd', 'osv']);
  });
  it('package-advisories', async () => {
    const { result } = await start(seeded(), 'package-advisories', {
      ecosystem: 'pypi',
      package: 'langflow',
    });
    expect(result.rows.map((r: { record: { sourceId: string } }) => r.record.sourceId)).toEqual(['PYSEC-1']);
  });
  it('company-breaches', async () => {
    const { result } = await start(seeded(), 'company-breaches', { company: 'widgets' });
    expect(result.rows).toHaveLength(1);
    const byKey = await start(seeded(), 'company-breaches', { company: 'cik:77' });
    expect(byKey.result.rows).toHaveLength(1);
  });
  it('epss-history: one row per day in range', async () => {
    const { result } = await start(seeded(), 'epss-history', {
      cve: 'CVE-2024-0001',
      from: '2026-11-01',
      to: '2026-11-23',
    });
    expect(result.rows).toEqual([
      { day: '2026-11-21', epss: 0.005, percentile: 0.4, model: 'v2025.03.14' },
      { day: '2026-11-22', epss: 0.02, percentile: 0.6, model: 'v2025.03.14' },
    ]);
    expect(result.sources).toEqual(['epss']);
  });

  it('runs DuckDB with argv ["-c", sql], an empty env, and params only in params.json', async () => {
    const api = seeded();
    const calls: { file: string; args: string[]; env: Record<string, string> }[] = [];
    let paramsFile = '';
    const { readFile, writeFile } = await import('node:fs/promises');
    const execFile: NonNullable<JobDeps['execFile']> = async (file, args, opts) => {
      calls.push({ file, args, env: opts.env });
      const sql = args[1] as string;
      const dir = /'([^']*)\/params\.json'/.exec(sql)?.[1] as string;
      paramsFile = await readFile(`${dir}/params.json`, 'utf8');
      await writeFile(`${dir}/out.ndjson`, '');
      return '';
    };
    const { result } = await start(
      api,
      'kev-additions',
      { from: '2025-05-01', to: '2025-05-31' },
      deps({ duckdb: () => '/usr/bin/duckdb', execFile }),
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]?.file).toBe('/usr/bin/duckdb');
    expect(calls[0]?.args[0]).toBe('-c');
    expect(calls[0]?.args).toHaveLength(2);
    expect(calls[0]?.env).toEqual({});
    expect(calls[0]?.args[1]).not.toContain('2025-05-01');
    expect(JSON.parse(paramsFile)).toEqual({ from: '2025-05-01', to: '2025-05-31' });
    expect(result.rows).toEqual([]);
  });

  it('a Parquet part without DuckDB fails query_failed', async () => {
    const api = seeded();
    api.store.set('lake/records/cisa-kev/2026/part-01HZC.parquet', new Uint8Array([1]));
    api.store.set(
      `jobs/${job().id}/request.json`,
      new TextEncoder().encode(request('kev-additions', { from: '2025-05-01', to: '2025-05-31' })),
    );
    const { ctx, logs } = fakeCtx(api);
    await expect(run(job({ kind: 'deep-query' }), ctx, deps())).rejects.toThrow('deep-query: query_failed');
    expect(logs.some((l) => l.msg === 'duckdb missing')).toBe(true);
  });
  it('fails when 1.1.1.1 answers, before reading anything', async () => {
    const api = seeded();
    const { ctx } = fakeCtx(api);
    const reached = (async (url: unknown) => {
      expect(String(url)).toBe('https://1.1.1.1/');
      return new Response('hello');
    }) as unknown as typeof fetch;
    await expect(run(job({ kind: 'deep-query' }), ctx, deps({ fetch: reached }))).rejects.toThrow(
      'deep-query: egress not restricted',
    );
    expect(api.store.has(`jobs/${job().id}/result.json`)).toBe(false);
  });
  it('a missing or invalid request.json fails invalid_params', async () => {
    const api = seeded();
    const { ctx } = fakeCtx(api);
    await expect(run(job({ kind: 'deep-query' }), ctx, deps())).rejects.toThrow('deep-query: invalid_params');
    api.store.set(
      `jobs/${job().id}/request.json`,
      new TextEncoder().encode(request('cve-history', { cve: "x' OR 1=1" })),
    );
    await expect(run(job({ kind: 'deep-query' }), ctx, deps())).rejects.toThrow('deep-query: invalid_params');
    api.store.set(`jobs/${job().id}/request.json`, new TextEncoder().encode('not json'));
    await expect(run(job({ kind: 'deep-query' }), ctx, deps())).rejects.toThrow('deep-query: invalid_params');
    expect(api.puts).toEqual([]);
  });
  it('fails scan_too_large before downloading', async () => {
    const api = seeded();
    let gets = 0;
    const get = api.getObject;
    api.getObject = async (k) => {
      if (!k.endsWith('request.json')) gets++;
      return get(k);
    };
    for (let i = 0; i < MAX_SCAN_OBJECTS + 1; i++)
      api.store.set(`lake/records/cisa-kev/2026/part-${i}.parquet`, new Uint8Array(1));
    api.store.set(
      `jobs/${job().id}/request.json`,
      new TextEncoder().encode(request('kev-additions', { from: '2025-05-01', to: '2025-05-31' })),
    );
    const { ctx } = fakeCtx(api);
    await expect(run(job({ kind: 'deep-query' }), ctx, deps())).rejects.toThrow('deep-query: scan_too_large');
    expect(gets).toBe(0);
  });
  it('drops rows and sets truncated when the JSON is over 5 MiB', async () => {
    const api = fakeApi();
    const big = 'x'.repeat(100_000);
    const rows = Array.from({ length: 80 }, (_, i) =>
      lakeRow('osv', '01HZA', i, {
        source: 'osv',
        sourceId: `S${i}`,
        vulnKey: null,
        status: 'active',
        modified: '2025-01-01',
        affected: [{ ecosystem: 'npm', name: 'big' }],
        pad: big,
      }),
    );
    api.store.set(
      'lake/records/osv/2026/part-01HZA.ndjson.gz',
      new Uint8Array(gzipSync(`${rows.map((r) => JSON.stringify(r)).join('\n')}\n`)),
    );
    const { result } = await start(api, 'package-advisories', { ecosystem: 'npm', package: 'big' });
    expect(result.truncated).toBe(true);
    expect(result.rowCount).toBeLessThan(80);
    expect(result.rowCount).toBe(result.rows.length);
  });
});
