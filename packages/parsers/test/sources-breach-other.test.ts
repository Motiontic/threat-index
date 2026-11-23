import type { AdvisoryRecord, NoticeRecord } from '@ti/core/types';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { fetch as feedFetch } from '../../patterns/src/feed';
import { fetch as fingerprintFetch } from '../../patterns/src/fingerprint';
import { makeCtx, reply, route } from '../../patterns/test/helpers';
import { loadParser } from '../src/load';

const src = (id: string) => {
  const s = SOURCE_BY_ID.get(id);
  if (!s) throw new Error(`no source ${id}`);
  return s;
};

const HIBP_URL = 'https://haveibeenpwned.com/api/v3/breaches';
const CISA_URL = 'https://www.cisa.gov/cybersecurity-advisories/all.xml';

describe('breach and advisory sources', () => {
  it('hibp: parser, pull, pattern, licence and credit', async () => {
    const s = src('hibp');
    expect(s.parser).toBe('hibp');
    expect(s.pattern).toBe('fingerprint');
    expect(s.licence).toBe('on');
    expect(s.credit).toBe('Source: Have I Been Pwned (haveibeenpwned.com, CC BY 4.0)');
    expect(s.pull).toEqual({ fingerprint: { url: HIBP_URL, format: 'json', key: 'Name' } });
    expect(typeof (await loadParser('hibp')).parse).toBe('function');
  });

  it('cisa-advisories: parser, pull, pattern, licence and credit', async () => {
    const s = src('cisa-advisories');
    expect(s.parser).toBe('cisa-advisories');
    expect(s.pattern).toBe('feed');
    expect(s.licence).toBe('on');
    expect(s.credit).toBe('Source: CISA advisories');
    expect(s.pull).toEqual({ feed: { url: CISA_URL, order: 'newest-first' } });
    expect(typeof (await loadParser('cisa-advisories')).parse).toBe('function');
  });

  it('vcdb: parser, pull, pattern, licence and credit', async () => {
    const s = src('vcdb');
    expect(s.parser).toBe('vcdb');
    expect(s.pattern).toBe('git');
    expect(s.licence).toBe('ask');
    expect(s.credit).toBe('Source: VERIS Community Database (vz-risk/VCDB, CC BY-SA 4.0)');
    expect(s.pull).toEqual({
      git: {
        repo: 'vz-risk/VCDB',
        branch: 'master',
        include: ['data/json/validated/*.json', 'data/json/submitted/*.json'],
      },
    });
    expect(typeof (await loadParser('vcdb')).parse).toBe('function');
  });

  it('uk-ico is unchanged: heavy, quarterly, on, no parser, no pull', () => {
    const s = src('uk-ico');
    expect(s.pattern).toBe('heavy');
    expect(s.cadence).toBe('quarterly');
    expect(s.licence).toBe('on');
    expect(s.heavy).toBe(true);
    expect(s.parser).toBeUndefined();
    expect(s.pull).toBeUndefined();
  });

  it('hibp through the fingerprint pattern: 8 items, 3 notices', async () => {
    const h = makeCtx({
      source: src('hibp'),
      routes: [
        route(HIBP_URL, reply(fixture('hibp', 'breaches.json'), 200, { 'content-type': 'application/json' })),
      ],
    });
    const res = await fingerprintFetch(h.ctx);
    expect(res.items).toHaveLength(8);
    const { parse } = await loadParser('hibp');
    const notices: NoticeRecord[] = [];
    for (const item of res.items) {
      const out = parse(item.body);
      notices.push(...((Array.isArray(out) ? out : out.records) as NoticeRecord[]));
    }
    expect(notices.map((n) => n.noticeId)).toEqual(['Adobe', 'Bromcom', 'AllegedATT']);
  });

  it('cisa-advisories through the feed pattern: 5 items, 8 records', async () => {
    const h = makeCtx({
      source: src('cisa-advisories'),
      routes: [
        route(
          CISA_URL,
          reply(fixture('cisa-advisories', 'all.xml'), 200, { 'content-type': 'application/rss+xml' }),
        ),
      ],
    });
    const res = await feedFetch(h.ctx);
    expect(res.items).toHaveLength(5);
    const { parse } = await loadParser('cisa-advisories');
    const recs: AdvisoryRecord[] = [];
    for (const item of res.items) {
      const out = parse(item.body);
      recs.push(...((Array.isArray(out) ? out : out.records) as AdvisoryRecord[]));
    }
    expect(recs).toHaveLength(8);
    expect(new Set(recs.map((r) => r.sourceId)).size).toBe(8);
  });
});
