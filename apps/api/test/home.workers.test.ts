import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import seed from './fixtures/world-seed.sql?raw';

// Same stub-middleware approach as world.workers.test.ts: signed in only with the test header, which skips the cache.
const { Hono } = await import('hono');
const { default: home } = await import('../src/routes/home');
const app = new Hono();
app.use('/v1/*', async (c, next) => {
  const user = c.req.header('x-test-user');
  c.set('clerkAuth' as never, (() => (user ? { userId: user } : { userId: null })) as never);
  await next();
});
app.route('/', home as never);

const E = env as unknown as { DB_WORLD: D1Database; DB_VULNS: D1Database; DB_SIGNALS: D1Database };

async function get(anon = false) {
  const ctx = createExecutionContext();
  const res = await app.fetch(
    new Request('https://api.test/v1/home', anon ? undefined : { headers: { 'x-test-user': 'user_1' } }),
    env as never,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}
// biome-ignore lint/suspicious/noExplicitAny: test helper over JSON
const json = async (res: Response) => (await res.json()) as any;
const pad = (n: number) => String(n).padStart(2, '0');

beforeAll(async () => {
  await E.DB_WORLD.batch(
    seed
      .split('\n')
      .filter((l) => l.startsWith('INSERT'))
      .map((l) => E.DB_WORLD.prepare(l)),
  );
  const vulns: D1PreparedStatement[] = [];
  const signals: D1PreparedStatement[] = [];
  // 12 CVEs, published 2025-03-01..12; the odd ones are also exploited (KEV) with a public exploit.
  for (let i = 1; i <= 12; i++) {
    const key = `CVE-2025-${1000 + i}`;
    vulns.push(
      E.DB_VULNS.prepare(
        `INSERT INTO vulns (key, kind, title, summary, published, modified, cvss, sources, hot)
         VALUES (?1,'cve',?2,'s',?3,'2025-04-01',?4,'["nvd"]',1)`,
      ).bind(key, `Flaw ${i}`, `2025-03-${pad(i)}`, 5 + (i % 5)),
    );
    signals.push(
      E.DB_SIGNALS.prepare(
        `INSERT INTO signals (vuln_key, kind, source, ref, first_seen) VALUES (?1,'exploited_wild','cisa-kev',?2,?3)`,
      ).bind(key, key, `2025-04-${pad(i)}T00:00:00Z`),
    );
    // A second source on the same vulnerability must not make it appear twice.
    signals.push(
      E.DB_SIGNALS.prepare(
        `INSERT INTO signals (vuln_key, kind, source, ref, first_seen) VALUES (?1,'poc','exploit-db',?2,?3)`,
      ).bind(key, `EDB-${i}`, `2025-05-${pad(i)}T00:00:00Z`),
    );
    signals.push(
      E.DB_SIGNALS.prepare(
        `INSERT INTO signals (vuln_key, kind, source, ref, first_seen) VALUES (?1,'public_exploit','nuclei',?2,?3)`,
      ).bind(key, `N-${i}`, `2025-05-${pad(i)}T01:00:00Z`),
    );
    signals.push(
      E.DB_SIGNALS.prepare(
        `INSERT INTO changes (id, entity_key, kind, old, new, at, source) VALUES (?1,?2,'newly_exploited',NULL,'kev',?3,'cisa-kev')`,
      ).bind(`c${i}`, key, `2025-04-${pad(i)}T00:00:00Z`),
    );
  }
  vulns.push(
    E.DB_VULNS.prepare(
      `INSERT INTO vulns (key, kind, title, summary, published, modified, sources, hot)
       VALUES ('MAL-2025-1','mal','Bad package','s','2025-06-01','2025-06-01','["osv"]',1)`,
    ),
    // Not hot: never counted or listed.
    E.DB_VULNS.prepare(
      `INSERT INTO vulns (key, kind, title, summary, published, modified, sources, hot)
       VALUES ('CVE-2020-0001','cve','Cold','s','2025-12-31','2025-12-31','["nvd"]',0)`,
    ),
  );
  await E.DB_VULNS.batch(vulns);
  await E.DB_SIGNALS.batch(signals);
});

describe('GET /v1/home', () => {
  it('answers counts, lists and changes in one body', async () => {
    const res = await get();
    expect(res.status).toBe(200);
    const body = await json(res);
    expect(Object.keys(body).sort()).toEqual(['changes', 'counts', 'lists']);
    expect(Object.keys(body.lists).sort()).toEqual(
      ['aiIncidents', 'breaches', 'exploited', 'exploits', 'maliciousPackages', 'vulnerabilities'].sort(),
    );
    expect(body.counts).toMatchObject({
      vulnerabilities: 12, // the cold CVE and the MAL- row are not vulnerabilities
      exploited: 12,
      exploits: 12,
      maliciousPackages: 1,
      aiIncidents: 2, // AVID-1 and AIAAIC-1; gated and hidden ones are not counted
      cyberOperations: 1,
      breaches: 4, // the event whose only notice is from a hidden source is not counted
      techniques: 6,
    });
  });

  it('caps every list at 10, newest first, with the signal that makes the item notable', async () => {
    const { lists, changes } = await json(await get());
    for (const l of Object.values(lists) as unknown[][]) expect(l.length).toBeLessThanOrEqual(10);
    expect(lists.vulnerabilities).toHaveLength(10);
    expect(lists.vulnerabilities.map((i: { key: string }) => i.key)[0]).toBe('CVE-2025-1012');
    expect(lists.vulnerabilities[0]).toMatchObject({ type: 'vuln', title: 'Flaw 12', date: '2025-03-12' });
    expect(lists.vulnerabilities[0].signal).toMatch(/^CVSS \d\.\d$/);
    expect(lists.exploited).toHaveLength(10);
    expect(lists.exploited[0]).toMatchObject({ key: 'CVE-2025-1012', type: 'vuln' });
    expect(lists.exploited[0].signal).toMatch(/12 Apr$/);
    const dates = lists.exploited.map((i: { date: string }) => i.date);
    expect(dates).toEqual([...dates].sort().reverse());
    // One vulnerability appears once even with several exploit signals.
    const exploitKeys = lists.exploits.map((i: { key: string }) => i.key);
    expect(new Set(exploitKeys).size).toBe(exploitKeys.length);
    expect(lists.exploits).toHaveLength(10);
    expect(lists.maliciousPackages).toEqual([
      expect.objectContaining({ key: 'MAL-2025-1', type: 'mal', date: '2025-06-01' }),
    ]);
    expect(changes).toHaveLength(10);
    expect(changes[0]).toMatchObject({ key: 'CVE-2025-1012', kind: 'newly_exploited', type: 'vuln' });
    expect(changes[0].title).toBe('Flaw 12');
  });

  it('lists only visible, ungated incidents and breaches', async () => {
    const { lists } = await json(await get());
    expect(lists.aiIncidents.map((i: { key: string }) => i.key)).toEqual(['AVID-1', 'AIAAIC-1']);
    expect(lists.aiIncidents[0]).toMatchObject({ source: 'avid', type: 'ai', date: '2024-02-01' });
    const breachKeys = lists.breaches.map((i: { key: string }) => i.key);
    expect(breachKeys).not.toContain('domain:hidden.test@2024-06-01');
    expect(lists.breaches[0]).toMatchObject({ type: 'breach' });
    expect(lists.breaches[0].signal).toMatch(/notices?$/);
  });

  it('is cached for anonymous callers and never for signed-in ones', async () => {
    const anon = await get(true);
    expect(anon.status).toBe(200);
    expect(anon.headers.get('cache-control')).toBe('public, max-age=300');
    const signed = await get();
    expect(signed.headers.get('cache-control')).toBe('private, no-store');
  });

  it('reads its lists through the new indexes', async () => {
    const plan = async (db: D1Database, sql: string) =>
      JSON.stringify((await db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all()).results);
    expect(
      await plan(
        E.DB_VULNS,
        `SELECT key FROM vulns WHERE hot = 1 AND substr(key, 1, 4) != 'MAL-' AND published IS NOT NULL ORDER BY published DESC LIMIT 10`,
      ),
    ).toContain('vulns_published_vuln');
    expect(
      await plan(
        E.DB_VULNS,
        `SELECT key FROM vulns WHERE hot = 1 AND substr(key, 1, 4) = 'MAL-' AND published IS NOT NULL ORDER BY published DESC LIMIT 10`,
      ),
    ).toContain('vulns_published_mal');
    expect(
      await plan(
        E.DB_SIGNALS,
        `SELECT vuln_key FROM signals WHERE kind IN ('exploited_wild') AND source IN ('cisa-kev') ORDER BY first_seen DESC LIMIT 60`,
      ),
    ).toContain('signals_by_kind_seen');
  });
});
