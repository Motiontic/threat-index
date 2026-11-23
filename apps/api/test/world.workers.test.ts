import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import seed from './fixtures/world-seed.sql?raw';

// Same stub-middleware approach as public-api.workers.test.ts: the world routes on a test app, signed in only
// with the test header. Signed-in requests skip the cache, so most tests use them; the cache tests go anonymous.
const { Hono } = await import('hono');
const { default: breaches } = await import('../src/routes/breaches');
const { default: incidents } = await import('../src/routes/incidents');
const { default: techniques } = await import('../src/routes/techniques');
const app = new Hono();
app.use('/v1/*', async (c, next) => {
  const user = c.req.header('x-test-user');
  c.set('clerkAuth' as never, (() => (user ? { userId: user } : { userId: null })) as never);
  await next();
});
for (const r of [breaches, incidents, techniques]) app.route('/', r as never);

const E = env as unknown as { DB_WORLD: D1Database; DB_VULNS: D1Database; SETTINGS: KVNamespace };

async function get(path: string, anon = false) {
  const ctx = createExecutionContext();
  const res = await app.fetch(
    new Request(`https://api.test${path}`, anon ? undefined : { headers: { 'x-test-user': 'user_1' } }),
    env as never,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}
// biome-ignore lint/suspicious/noExplicitAny: test helper over JSON
const json = async (res: Response) => (await res.json()) as any;

const ACME = encodeURIComponent('cik:0000000001@2024-03-04');

beforeAll(async () => {
  const stmts = seed
    .split('\n')
    .filter((l) => l.startsWith('INSERT'))
    .map((l) => E.DB_WORLD.prepare(l));
  await E.DB_WORLD.batch(stmts);
  for (const [key, cvss, kev] of [
    ['CVE-2024-0001', 9.8, '2024-01-01'],
    ['CVE-2024-0002', 5.0, null],
  ] as const) {
    await E.DB_VULNS.prepare(
      `INSERT INTO vulns (key, kind, title, summary, published, modified, cvss, cvss_version, cvss_source, cwe, kev_added, ransomware, epss, sources, doc_key)
       VALUES (?1,'cve',?2,'s','2024-01-01','2024-01-02',?3,'3.1','nvd','[]',?4,0,0.1,'["nvd"]','docs/x')`,
    )
      .bind(key, `Title ${key}`, cvss, kev)
      .run();
  }
});

describe('breaches', () => {
  it('lists events with a visible notice, newest first, with no total', async () => {
    const body = await json(await get('/v1/breaches'));
    const keys = body.items.map((i: { key: string }) => i.key);
    expect(keys).toEqual([
      'cik:0000000002@2024-05-01',
      'cik:0000000001@2024-03-04',
      'domain:purex.test@2023-02-01',
      'domain:pure.test@2023-01-01',
    ]);
    expect(keys).not.toContain('domain:hidden.test@2024-06-01');
    expect(body.next).toBeNull();
    expect(JSON.stringify(body)).not.toMatch(/total/i);
  });

  it('keeps one count per unit and jurisdiction and never sums', async () => {
    const d = await json(await get(`/v1/breaches/${ACME}`));
    expect(d.counts).toEqual([
      { unit: 'accounts', jurisdiction: null, count: 1200 },
      { unit: 'individuals', jurisdiction: 'GB', count: 700 },
      { unit: 'individuals', jurisdiction: 'US', count: 500 },
    ]);
    expect(d.jurisdictions).toEqual(['GB', 'US']);
    expect(d.dates).toEqual({ from: '2024-03-01', to: '2024-03-04' });
    expect(d.company).toEqual({ key: 'cik:0000000001', name: 'Acme Corp' });
    expect('total' in d).toBe(false);
  });

  it('a wait-source notice changes nothing: counts, jurisdictions, noticeCount, sources, credits', async () => {
    const d = await json(await get(`/v1/breaches/${ACME}`));
    expect(d.noticeCount).toBe(5); // H1, O1, O2, U1 and the link notice; not W1
    expect(d.sources).toEqual(['databreaches-net', 'hhs-ocr', 'hibp', 'uk-ico']);
    expect(d.credits.map((c: { sourceId: string }) => c.sourceId)).not.toContain('ransomware-live');
    const text = JSON.stringify(d);
    expect(text).not.toContain('9999999');
    expect(text).not.toContain('ZZ');
    expect(text).not.toContain('wait.example.test');
    expect(d.notices.map((n: { source: string }) => n.source)).not.toContain('ransomware-live');
    const list = await json(await get('/v1/breaches'));
    const row = list.items.find((i: { key: string }) => i.key === 'cik:0000000001@2024-03-04');
    expect(row.noticeCount).toBe(5);
    expect(JSON.stringify(list)).not.toContain('ransomware-live');
  });

  it('a hidden notice with the earliest date moves neither firstSeen, dates nor the list order', async () => {
    const d = await json(await get(`/v1/breaches/${ACME}`));
    expect(d.firstSeen).toBe('2024-03-10'); // H1; W1 (hidden) is 2022-12-01
    expect(d.dates).toEqual({ from: '2024-03-01', to: '2024-03-04' }); // not 2022-11-01
    const list = await json(await get('/v1/breaches'));
    const row = list.items.find((i: { key: string }) => i.key === 'cik:0000000001@2024-03-04');
    expect(row.firstSeen).toBe('2024-03-10');
    expect(row.dates).toEqual({ from: '2024-03-01', to: '2024-03-04' });
    expect(list.items.map((i: { key: string }) => i.key).indexOf('cik:0000000001@2024-03-04')).toBe(1);
  });

  it('link notices carry only the link fields and add no count or jurisdiction', async () => {
    const d = await json(await get(`/v1/breaches/${ACME}`));
    const link = d.notices.find((n: { source: string }) => n.source === 'databreaches-net');
    expect(Object.keys(link).sort()).toEqual(['display', 'name', 'noticeId', 'notified', 'source', 'url']);
    expect(link.display).toBe('link');
    expect(d.jurisdictions).not.toContain('FR');
    expect(d.counts.some((c: { count: number }) => c.count === 5555)).toBe(false);
    const full = d.notices.find((n: { noticeId: string }) => n.noticeId === 'O1');
    expect(full).toMatchObject({ display: 'full', count: 500, countUnit: 'individuals', jurisdiction: 'US' });
    expect(full.dataTypes).toEqual(['email', 'name']);
    // sorted by notified, then source
    const dates = d.notices.map((n: { notified: string }) => n.notified);
    expect(dates).toEqual([...dates].sort());
  });

  it('an event whose only notices are hidden is 404 and not listed', async () => {
    const res = await get(`/v1/breaches/${encodeURIComponent('domain:hidden.test@2024-06-01')}`);
    expect(res.status).toBe(404);
    expect(await json(res)).toEqual({ error: 'not_found' });
    expect((await get('/v1/breaches/nope')).status).toBe(404);
  });

  it('q matches the company or a visible notice name; % and _ are literal', async () => {
    const names = async (q: string) =>
      (await json(await get(`/v1/breaches?q=${encodeURIComponent(q)}`))).items.map(
        (i: { key: string }) => i.key,
      );
    expect(await names('globex')).toEqual(['cik:0000000002@2024-05-01']);
    expect(await names('Acme Ltd')).toEqual(['cik:0000000001@2024-03-04']);
    expect(await names('acme (wait)')).toEqual([]); // only the hidden notice has that name
    expect(await names('100%')).toEqual(['domain:pure.test@2023-01-01']);
    expect(await names('pure_')).toEqual(['domain:pure.test@2023-01-01']);
    expect(await names('%')).toEqual(['domain:pure.test@2023-01-01']);
    expect(await names('_')).toEqual(['domain:pure.test@2023-01-01']);
  });

  it('pages 25 at a time and sets next', async () => {
    const stmts: D1PreparedStatement[] = [];
    for (let i = 0; i < 26; i++) {
      const k = `domain:page${String(i).padStart(2, '0')}.test`;
      const ek = `${k}@2022-01-01`;
      stmts.push(
        E.DB_WORLD.prepare("INSERT INTO companies (key, name) VALUES (?1, 'Pager Co')").bind(k),
        E.DB_WORLD.prepare(
          "INSERT INTO breach_events (key, company_key, first_seen, modified) VALUES (?1, ?2, '2022-01-01', 'm')",
        ).bind(ek, k),
        E.DB_WORLD.prepare(
          "INSERT INTO breach_notices (source, notice_id, company_key, raw_name, count_unit, event_key, modified) VALUES ('hibp', ?1, ?2, 'Pager Co', 'not_stated', ?3, 'm')",
        ).bind(`pg${i}`, k, ek),
      );
    }
    await E.DB_WORLD.batch(stmts);
    const one = await json(await get('/v1/breaches?q=pager'));
    expect(one.items).toHaveLength(25);
    expect(one.page).toBe(1);
    expect(one.next).toBe(2);
    const two = await json(await get('/v1/breaches?q=pager&page=2'));
    expect(two.items).toHaveLength(1);
    expect(two.next).toBeNull();
    expect(one.items.map((i: { key: string }) => i.key)).toEqual(
      [...one.items.map((i: { key: string }) => i.key)].sort().reverse(),
    );
  });

  it('answers each 400', async () => {
    for (const [path, error] of [
      ['/v1/breaches?q=%00x', 'bad_query'],
      ['/v1/breaches?q=%20%20', 'bad_query'],
      [`/v1/breaches?q=${'a'.repeat(101)}`, 'bad_query'],
      ['/v1/breaches?page=0', 'bad_page'],
      ['/v1/breaches?page=41', 'bad_page'],
      ['/v1/breaches?page=x', 'bad_page'],
      [`/v1/breaches/${'a'.repeat(201)}`, 'bad_id'],
      ['/v1/breaches/caf%C3%A9', 'bad_id'],
    ] as const) {
      const res = await get(path);
      expect([path, res.status, (await json(res)).error]).toEqual([path, 400, error]);
    }
    expect((await get('/v1/breaches?page=40&junk=1')).status).toBe(200);
  });
});

describe('incidents', () => {
  it('lists visible, non-gated incidents: date desc, nulls last', async () => {
    const body = await json(await get('/v1/incidents'));
    expect(body.items.map((i: { incidentId: string }) => i.incidentId)).toEqual([
      'DBN-2',
      'DBN-1',
      'CFR-1',
      'AVID-1',
      'AIAAIC-1',
    ]);
    const text = JSON.stringify(body);
    expect(text).not.toContain('AVID-2'); // gated
    expect(text).not.toContain('AIID-1'); // wait source
    expect(text).not.toContain('"aiid"');
    expect(body.credits.map((c: { sourceId: string }) => c.sourceId)).not.toContain('aiid');
  });

  it('filters by kind, with the cyber shorthand, and by q literally', async () => {
    const ids = async (qs: string) =>
      (await json(await get(`/v1/incidents?${qs}`))).items.map((i: { incidentId: string }) => i.incidentId);
    expect(await ids('kind=ai')).toEqual(['AVID-1', 'AIAAIC-1']);
    expect(await ids('kind=cyber')).toEqual(['DBN-2', 'DBN-1', 'CFR-1']);
    expect(await ids('kind=cyber_op&kind=ai')).toEqual(['CFR-1', 'AVID-1', 'AIAAIC-1']);
    expect(await ids('q=100%25')).toEqual(['DBN-1']);
    expect(await ids('q=injection')).toEqual(['AVID-1']);
    expect((await get('/v1/incidents?kind=bogus')).status).toBe(400);
    expect((await json(await get('/v1/incidents?kind=bogus'))).error).toBe('bad_kind');
  });

  it('full detail resolves technique names; unknown ids keep only the id', async () => {
    const d = await json(await get('/v1/incidents/avid/AVID-1'));
    expect(d.display).toBe('full');
    expect(d.entities).toEqual(['Acme Corp']);
    expect(d.techniques).toEqual([{ id: 'AML.T0051', name: 'LLM Prompt Injection' }, { id: 'AML.T9999' }]);
    expect(d.credits.map((c: { sourceId: string }) => c.sourceId)).toEqual(['avid']);
  });

  it('link incidents carry only id, title, date, url and kind, with empty lists', async () => {
    const d = await json(await get('/v1/incidents/databreaches-net/DBN-2'));
    expect(Object.keys(d).sort()).toEqual([
      'credits',
      'date',
      'display',
      'entities',
      'incidentId',
      'kind',
      'source',
      'techniques',
      'title',
      'url',
    ]);
    expect(d.entities).toEqual([]);
    expect(d.techniques).toEqual([]);
    expect(JSON.stringify(d)).not.toContain('Secret entity');
    // a non-http url is dropped
    const bad = await json(await get('/v1/incidents/databreaches-net/DBN-1'));
    expect('url' in bad).toBe(false);
  });

  it('404s gated, hidden and missing; 400s a bad source or id', async () => {
    for (const p of ['/v1/incidents/avid/AVID-2', '/v1/incidents/aiid/AIID-1', '/v1/incidents/avid/NOPE'])
      expect((await get(p)).status).toBe(404);
    for (const p of ['/v1/incidents/not-a-source/x', `/v1/incidents/avid/${'a'.repeat(201)}`])
      expect(await json(await get(p))).toEqual({ error: 'bad_id' });
  });
});

describe('techniques', () => {
  it('lists by framework then id, filters, and matches q on id or name', async () => {
    const all = await json(await get('/v1/techniques'));
    expect(all.items.map((i: { id: string }) => i.id)).toEqual([
      'AML.T0051',
      'T1566',
      'T1566.001',
      'T1566.002',
      'CAPEC-63',
      'CWE-79',
    ]);
    expect(all.credits.map((c: { sourceId: string }) => c.sourceId).sort()).toEqual([
      'capec',
      'cwe',
      'mitre-atlas',
      'mitre-attack',
    ]);
    const ids = async (qs: string) =>
      (await json(await get(`/v1/techniques?${qs}`))).items.map((i: { id: string }) => i.id);
    expect(await ids('framework=cwe')).toEqual(['CWE-79']);
    expect(await ids('framework=cwe&framework=capec')).toEqual(['CAPEC-63', 'CWE-79']);
    expect(await ids('q=t1566.00')).toEqual(['T1566.001', 'T1566.002']);
    expect(await ids('q=phishing')).toEqual(['T1566', 'T1566.001', 'T1566.002']);
    expect(await ids('q=spearphishing%20link')).toEqual(['T1566.002']);
    expect(await ids('q=%25')).toEqual([]);
    expect((await json(await get('/v1/techniques?framework=x'))).error).toBe('bad_framework');
  });

  it('detail has parent, children, linked vulns (missing ones dropped) and credits', async () => {
    const d = await json(await get('/v1/techniques/T1566'));
    expect(d.summary).toBe('Adversaries send phishing messages.');
    expect(d.children.map((c: { id: string }) => c.id)).toEqual(['T1566.001', 'T1566.002']);
    expect(d.vulns).toEqual([
      { key: 'CVE-2024-0001', title: 'Title CVE-2024-0001', cvss: 9.8, exploited: true },
      { key: 'CVE-2024-0002', title: 'Title CVE-2024-0002', cvss: 5, exploited: false },
    ]);
    expect(d.vulnsMore).toBe(false);
    expect(d.credits.map((c: { sourceId: string }) => c.sourceId)).toEqual(['mitre-attack']);
    const child = await json(await get('/v1/techniques/T1566.001'));
    expect(child.parentRef).toEqual({ id: 'T1566', name: 'Phishing' });
    expect(child.vulns).toEqual([]);
  });

  it('vulnsMore is set when there are more than 50 links', async () => {
    const stmts = Array.from({ length: 51 }, (_, i) =>
      E.DB_WORLD.prepare("INSERT INTO vuln_techniques (vuln_key, technique_id) VALUES (?1, 'CWE-79')").bind(
        `CVE-2023-${String(i).padStart(4, '0')}`,
      ),
    );
    await E.DB_WORLD.batch(stmts);
    const d = await json(await get('/v1/techniques/CWE-79'));
    expect(d.vulnsMore).toBe(true);
  });

  it('400s a bad id and 404s a missing one', async () => {
    expect(await json(await get('/v1/techniques/foo'))).toEqual({ error: 'bad_id' });
    expect(await json(await get('/v1/techniques/T1566.1'))).toEqual({ error: 'bad_id' });
    expect((await get('/v1/techniques/T9999')).status).toBe(404);
  });
});

describe('licence overrides, caching', () => {
  it('a KV override to hidden takes effect', async () => {
    await E.SETTINGS.put('source:hhs-ocr', JSON.stringify({ display: 'hidden' }));
    try {
      const d = await json(await get(`/v1/breaches/${ACME}`));
      expect(d.sources).not.toContain('hhs-ocr');
      expect(d.counts.some((c: { jurisdiction: string }) => c.jurisdiction === 'US')).toBe(false);
      const list = await json(await get('/v1/breaches?q=globex')); // its only notice is hhs-ocr
      expect(list.items).toEqual([]);
    } finally {
      await E.SETTINGS.delete('source:hhs-ocr');
    }
    await E.SETTINGS.put('source:cwe', JSON.stringify({ display: 'hidden' }));
    try {
      expect((await get('/v1/techniques/CWE-79')).status).toBe(404);
      const list = await json(await get('/v1/techniques'));
      expect(list.items.map((i: { id: string }) => i.id)).not.toContain('CWE-79');
    } finally {
      await E.SETTINGS.delete('source:cwe');
    }
  });

  it('anonymous responses are cached for 300 s; signed-in are private, no-store', async () => {
    const path = '/v1/techniques?framework=capec&q=xss';
    const first = await get(path, true);
    expect(first.status).toBe(200);
    expect(first.headers.get('cache-control')).toBe('public, max-age=300');
    await first.text();
    // change the data under the cache: a hit still shows the old answer
    await E.DB_WORLD.prepare("UPDATE techniques SET name = 'Changed' WHERE id = 'CAPEC-63'").run();
    const second = await json(await get(path, true));
    expect(second.items[0].name).toBe('Cross-Site Scripting (XSS)');
    const signed = await get(path);
    expect(signed.headers.get('cache-control')).toBe('private, no-store');
    expect((await json(signed)).items).toEqual([]); // q=xss no longer matches the changed name: live read
    await E.DB_WORLD.prepare(
      "UPDATE techniques SET name = 'Cross-Site Scripting (XSS)' WHERE id = 'CAPEC-63'",
    ).run();
  });

  it('builds the cache key from validated values only', async () => {
    const { cacheKey } = await import('../src/lib/world');
    expect(
      cacheKey('/v1/breaches', [
        ['page', 2],
        ['q', 'a b&c'],
      ]),
    ).toBe('/v1/breaches?page=2&q=a%20b%26c');
    // junk parameters do not reach the key: both requests share one cached answer
    await (await get('/v1/breaches?junk=1', true)).text();
    await E.DB_WORLD.prepare(
      "UPDATE companies SET name = 'Globex Changed' WHERE key = 'cik:0000000002'",
    ).run();
    const again = await json(await get('/v1/breaches?junk=2&page=1', true));
    expect(again.items[0].company.name).toBe('Globex Inc');
    await E.DB_WORLD.prepare("UPDATE companies SET name = 'Globex Inc' WHERE key = 'cik:0000000002'").run();
  });
});
