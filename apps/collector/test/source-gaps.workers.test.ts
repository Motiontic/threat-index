import { canIngest } from '@ti/core/licence';
import { loadParser } from '@ti/parsers/load';
import { patternFor } from '@ti/patterns/by-name';
import { SOURCES } from '@ti/sources/registry';
import { beforeEach, describe, expect, it } from 'vitest';
import kevFeed from '../../../fixtures/cisa-kev/real-feed.json';
import { MAX_STEPS_PER_RUN } from '../src/env';
import { dueSources, FIRST_RUN_HEAVY_PER_TICK, isHeavySource } from '../src/planner';
import { runStep } from '../src/step';
import {
  E,
  fakeJobs,
  getCursor,
  getRun,
  HOUR,
  mkDeps,
  msgBody,
  NOW,
  reset,
  result,
  seedRun,
} from './helpers';

beforeEach(reset);

const CRON = '0 */3 * * *';
const SEC_UA = 'Motiontic Threat Index ops@motiontic.com';

describe('cisa-kev pull', () => {
  it('fetches the feed, hands changed entries to the kev parser and stores the cursor', async () => {
    const urls: string[] = [];
    const seen: { kind: string; vulnKey: string }[] = [];
    const deps = mkDeps({
      patternFor,
      loadParser,
      fetch: (async (input: RequestInfo | URL) => {
        urls.push(String(input));
        return new Response(JSON.stringify(kevFeed), {
          headers: { 'content-type': 'application/json', etag: '"v1"' },
        });
      }) as typeof fetch,
      link: async (records) => {
        for (const r of records) seen.push(r as never);
        return { rows: [], docs: [], skipped: 0 };
      },
    });
    const body = msgBody('cisa-kev');
    expect(await runStep(body, 1, E, deps)).toEqual({ ack: true, status: 'ok' });
    expect(urls).toEqual([
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    ]);
    expect(await getRun(body.runId)).toMatchObject({ status: 'ok', error: null });
    expect(seen.filter((r) => r.kind === 'exploited_wild')).toHaveLength(kevFeed.vulnerabilities.length);
    expect(seen.some((r) => r.kind === 'ransomware')).toBe(true);
    const stored = JSON.parse((await getCursor('cisa-kev'))?.value ?? '{}');
    expect(stored.v).toBe(kevFeed.catalogVersion);
    expect(Object.keys(stored.h)).toHaveLength(kevFeed.vulnerabilities.length);
  });
});

describe('step limit', () => {
  it('ends the run ok, keeps the cursor and queues nothing; it is not "continuation not queued"', async () => {
    const jobs = fakeJobs({ failSend: true }); // must not even be called
    const env = { ...E, JOBS: jobs.queue };
    const body = msgBody('cisa-kev', { step: MAX_STEPS_PER_RUN });
    const deps = mkDeps({
      patternFor: () => ({ check: async () => 'changed', fetch: async () => result({ more: true }) }),
    });
    expect(await runStep(body, 1, env, deps)).toEqual({ ack: true, status: 'ok' });
    const run = await getRun(body.runId);
    expect(run?.status).toBe('ok');
    expect(run?.error).toContain('step limit');
    expect(run?.error).not.toContain('continuation not queued');
    expect(await getCursor('cisa-kev')).toMatchObject({ value: 't1' });
    expect(jobs.sent).toEqual([]);
  });

  it('the next planning tick starts the source again from the kept cursor', async () => {
    const body = msgBody('cisa-kev', { step: MAX_STEPS_PER_RUN });
    const deps = mkDeps({
      patternFor: () => ({ check: async () => 'changed', fetch: async () => result({ more: true }) }),
    });
    await runStep(body, 1, { ...E, JOBS: fakeJobs().queue }, deps);
    const later = new Date(NOW.getTime() + 3 * HOUR);
    const due = await dueSources(E, CRON, later);
    expect(due.find((d) => d.source.id === 'cisa-kev')?.from).toMatchObject({ value: 't1' });
  });

  it('a real JOBS.send failure still reports continuation not queued', async () => {
    const env = { ...E, JOBS: fakeJobs({ failSend: true }).queue };
    const body = msgBody('cisa-kev');
    const deps = mkDeps({
      patternFor: () => ({ check: async () => 'changed', fetch: async () => result({ more: true }) }),
    });
    expect(await runStep(body, 1, env, deps)).toEqual({ ack: true, status: 'failed' });
    expect(await getRun(body.runId)).toMatchObject({ status: 'failed', error: 'continuation not queued' });
  });
});

describe('SEC User-Agent', () => {
  const atom = '<feed xmlns="http://www.w3.org/2005/Atom"></feed>';
  const withUa = (ua: string | undefined, contact?: string) =>
    ({ ...E, USER_AGENT: ua, CONTACT_EMAIL: contact }) as typeof E;

  it('requests to sec.gov carry Motiontic Threat Index <contact> (contact from USER_AGENT)', async () => {
    const sent: { url: string; ua: string | null }[] = [];
    const deps = mkDeps({
      patternFor,
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        sent.push({ url: String(input), ua: new Headers(init?.headers).get('user-agent') });
        return new Response(atom, { headers: { 'content-type': 'application/atom+xml' } });
      }) as typeof fetch,
    });
    const env = withUa('ThreatIndex/0.1 (+https://github.com/Motiontic/threat-index; ops@motiontic.com)');
    await runStep(msgBody('sec-edgar'), 1, env, deps);
    expect(sent.length).toBeGreaterThan(0);
    for (const s of sent) {
      expect(new URL(s.url).hostname.endsWith('sec.gov')).toBe(true);
      expect(s.ua).toBe(SEC_UA);
    }
  });

  it('CONTACT_EMAIL wins over the address inside USER_AGENT; other sources keep USER_AGENT', async () => {
    const agents: Record<string, string> = {};
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async (ctx: { source: { id: string }; userAgent: string }) => {
          agents[ctx.source.id] = ctx.userAgent;
          return result({ items: [], more: false });
        },
      }),
    } as never);
    const ua = 'ThreatIndex/0.1 (+https://github.com/Motiontic/threat-index; old@example.org)';
    const env = withUa(ua, 'ops@motiontic.com');
    await runStep(msgBody('sec-edgar'), 1, env, deps);
    await runStep(msgBody('cisa-advisories'), 1, env, deps);
    expect(agents['sec-edgar']).toBe(SEC_UA);
    expect(agents['cisa-advisories']).toBe(ua);
  });

  it('with no contact configured SEC is skipped with a clear reason and nothing is fetched', async () => {
    let fetched = false;
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async () => {
          fetched = true;
          return result();
        },
      }),
    });
    for (const env of [
      withUa(undefined),
      withUa('ThreatIndex/0.1 (+https://github.com/Motiontic/threat-index; )'),
      withUa('ThreatIndex/0.1 (+https://github.com/Motiontic/threat-index)', 'not-an-email'),
    ]) {
      const body = msgBody('sec-edgar');
      expect(await runStep(body, 1, env, deps)).toEqual({ ack: true, status: 'skipped' });
      expect(await getRun(body.runId)).toMatchObject({
        status: 'skipped',
        error: 'no contact email configured (SEC requires one)',
      });
    }
    expect(fetched).toBe(false);
  });
});

describe('skip reasons', () => {
  it.each([
    ['zdi', 'link only: not ingested'],
    ['databreaches-net', 'link only: not ingested'],
    ['cisa-vulnrichment', 'read from CVE List records'],
  ])('%s is skipped with "%s"', async (id, reason) => {
    const body = msgBody(id);
    expect(await runStep(body, 1, E, mkDeps({ patternFor }))).toEqual({ ack: true, status: 'skipped' });
    expect(await getRun(body.runId)).toMatchObject({ status: 'skipped', error: reason });
  });

  it('another source without a pull config keeps the old reason', async () => {
    const body = msgBody('oracle');
    await runStep(body, 1, E, mkDeps({ patternFor }));
    expect(await getRun(body.runId)).toMatchObject({
      status: 'skipped',
      error: 'source has no pull config yet',
    });
  });
});

describe('first run regardless of cadence (fake clock, fresh database)', () => {
  const fetchable = SOURCES.filter((s) => s.pull !== undefined && canIngest(s.licence, undefined));
  const slow = fetchable.filter((s) => !['3h', 'with-cve-list'].includes(s.cadence));
  const heavy = fetchable.filter(isHeavySource);

  it('a daily, weekly and quarterly-cadence source is due on a 3-hourly tick when never run', async () => {
    const lightSlow = slow.filter((s) => !isHeavySource(s));
    expect(lightSlow.map((s) => s.cadence)).toEqual(expect.arrayContaining(['daily', 'weekly']));
    const ids = (await dueSources(E, CRON, NOW)).map((d) => d.source.id);
    for (const s of lightSlow) expect(ids).toContain(s.id);
  });

  it('after its first ok run the normal cadence applies again', async () => {
    const s = slow.find((x) => x.cadence === 'daily' && !isHeavySource(x));
    if (!s) throw new Error('no light daily source');
    await seedRun('r1', s.id, new Date(NOW.getTime() - 3 * HOUR), 'ok');
    const ids = (await dueSources(E, CRON, NOW)).map((d) => d.source.id);
    expect(ids).not.toContain(s.id);
    // the daily cron still runs it once a day has passed
    const later = new Date(NOW.getTime() + 22 * HOUR);
    expect((await dueSources(E, '45 14 * * *', later)).map((d) => d.source.id)).toContain(s.id);
  });

  it('a failed first run is retried on the next tick; a wait source never is', async () => {
    const s = slow.find((x) => !isHeavySource(x));
    if (!s) throw new Error('no slow source');
    await seedRun('r1', s.id, new Date(NOW.getTime() - 3 * HOUR), 'failed');
    const ids = (await dueSources(E, CRON, NOW)).map((d) => d.source.id);
    expect(ids).toContain(s.id);
    expect(ids).not.toContain('ransomware-live');
  });

  it('starts at most FIRST_RUN_HEAVY_PER_TICK never-run heavy sources per tick and covers all within a day', async () => {
    const started = new Set<string>();
    for (let tick = 0; tick < 8; tick++) {
      const at = new Date(NOW.getTime() + tick * 3 * HOUR);
      const due = await dueSources(E, CRON, at);
      const firstHeavy = due.filter((d) => isHeavySource(d.source) && !started.has(d.source.id));
      expect(firstHeavy.length).toBeLessThanOrEqual(FIRST_RUN_HEAVY_PER_TICK);
      for (const d of due) {
        const isHeavy = isHeavySource(d.source);
        await seedRun(`t${tick}-${d.source.id}`, d.source.id, at, isHeavy ? 'heavy' : 'ok');
        if (isHeavy) started.add(d.source.id);
      }
    }
    for (const s of heavy) expect(started.has(s.id)).toBe(true);
    expect(heavy.length).toBeLessThanOrEqual(8 * FIRST_RUN_HEAVY_PER_TICK);
    // first-day coverage: every fetchable source has a run
    const rows = await E.DB_CONTROL.prepare('SELECT DISTINCT source_id FROM runs').all<{
      source_id: string;
    }>();
    const have = new Set(rows.results.map((r) => r.source_id));
    for (const s of fetchable) expect(have.has(s.id)).toBe(true);
  });

  it('a heavy source whose first run failed counts against the cap and others rotate in', async () => {
    const first = await dueSources(E, CRON, NOW);
    const picked = first.filter((d) => isHeavySource(d.source)).map((d) => d.source.id);
    expect(picked).toHaveLength(FIRST_RUN_HEAVY_PER_TICK);
    for (const id of picked) await seedRun(`f-${id}`, id, NOW, 'failed');
    const next = (await dueSources(E, CRON, new Date(NOW.getTime() + 3 * HOUR))).map((d) => d.source.id);
    const nextHeavy = next.filter((id) => heavy.some((s) => s.id === id));
    expect(nextHeavy).toHaveLength(FIRST_RUN_HEAVY_PER_TICK);
    for (const id of picked) expect(nextHeavy).not.toContain(id); // never-attempted ones go first
  });

  it('the weekly and daily crons are capped too on a fresh database', async () => {
    for (const cron of ['0 5 * * 1', '45 14 * * *']) {
      const due = await dueSources(E, cron, NOW);
      expect(due.filter((d) => isHeavySource(d.source)).length).toBeLessThanOrEqual(FIRST_RUN_HEAVY_PER_TICK);
    }
  });
});
