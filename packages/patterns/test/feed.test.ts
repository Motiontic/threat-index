import type { Cursor } from '@ti/core/types';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { check, fetch, type LinkOnlyItem } from '../src/feed';
import { EXAMPLES, sourceWith } from './examples';
import { makeCtx, reply, route } from './helpers';

const URL_ = EXAMPLES['cisa-advisories'].feed.url;
const source = sourceWith('cisa-advisories');
const xml = fixture('cisa-advisories', 'pattern-all.xml');
const at = (key: string, etag?: string): Cursor => ({
  kind: 'version',
  value: key,
  ...(etag ? { etag } : {}),
});
const feedReply = (body: string, etag = '"f1"') =>
  reply(body, 200, { etag, 'content-type': 'application/rss+xml' });
const key = (n: number) => `icsa-25-${100 + n}-01`;

describe('feed', () => {
  it('check: 304, or the newest key equal to the cursor, is unchanged', async () => {
    const a = makeCtx({ source, cursor: at(key(1), '"f1"'), routes: [route(URL_, reply(null, 304))] });
    expect(await check(a.ctx)).toBe('unchanged');
    expect(a.requests[0]?.headers['if-none-match']).toBe('"f1"');
    const b = makeCtx({ source, cursor: at(key(1), '"f0"'), routes: [route(URL_, feedReply(xml))] });
    expect(await check(b.ctx)).toBe('unchanged');
    const c = makeCtx({ source, cursor: at(key(3), '"f0"'), routes: [route(URL_, feedReply(xml))] });
    expect(await check(c.ctx)).toBe('changed');
  });

  it('check: no cursor, or a mid-run one (no validator), is changed without a request', async () => {
    const a = makeCtx({ source });
    const b = makeCtx({ source, cursor: at(key(3)) });
    expect([await check(a.ctx), await check(b.ctx)]).toEqual(['changed', 'changed']);
    expect(a.requests.length + b.requests.length).toBe(0);
  });

  it('fetch on an empty feed with a null cursor commits nothing (no empty-valued cursor)', async () => {
    const empty = '<?xml version="1.0"?><rss version="2.0"><channel><title>t</title></channel></rss>';
    const h = makeCtx({ source, routes: [route(URL_, feedReply(empty))] });
    expect(await fetch(h.ctx)).toMatchObject({ items: [], receipt: null, more: false, nextCursor: null });
  });

  it('fetch with nothing new keeps the cursor', async () => {
    const cur = at(key(1), '"f0"');
    const h = makeCtx({ source, cursor: cur, routes: [route(URL_, feedReply(xml))] });
    expect(await fetch(h.ctx)).toMatchObject({ items: [], receipt: null, more: false, nextCursor: cur });
    const h304 = makeCtx({ source, cursor: cur, routes: [route(URL_, reply(null, 304))] });
    expect((await fetch(h304.ctx)).nextCursor).toBe(h304.ctx.cursor);
  });

  it('fetch: a null cursor does the first run in the Worker: all items, oldest first, one receipt line', async () => {
    const h = makeCtx({ source, runId: 'r', routes: [route(URL_, feedReply(xml))] });
    const r = await fetch(h.ctx);
    expect(r.heavy).toBeUndefined();
    expect(r.items.map((i) => i.id)).toEqual([6, 5, 4, 3, 2, 1].map(key));
    expect(r.nextCursor).toEqual(at(key(1), '"f1"'));
    expect(r.more).toBe(false);
    expect(r.items[0]?.body).toMatchObject({ title: 'Advisory 6' });
    const lines = String(r.receipt?.body).trim().split('\n');
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0] ?? '')).toMatchObject({ url: URL_, status: 200 });
    expect(r.receipt?.runId).toBe('r');
  });

  it('fetch: stops at the cursor key; the cursor becomes the newest key returned', async () => {
    const h = makeCtx({ source, cursor: at(key(4), '"f0"'), routes: [route(URL_, feedReply(xml))] });
    const r = await fetch(h.ctx);
    expect(r.items.map((i) => i.id)).toEqual([key(3), key(2), key(1)]);
    expect(r.nextCursor?.value).toBe(key(1));
  });

  it('fetch: over 40 new gives the oldest 40 with more and no validator, then the rest', async () => {
    const items = Array.from(
      { length: 95 },
      (_, i) => `<item><title>T${i}</title><link>https://x.test/${i}</link><guid>g${95 - i}</guid></item>`,
    ).join('');
    const big = `<rss version="2.0"><channel>${items}</channel></rss>`;
    const routes = [route(URL_, feedReply(big, '"big"'))];
    const r1 = await fetch(makeCtx({ source, routes }).ctx);
    expect(r1.items).toHaveLength(40);
    expect(r1.items[0]?.id).toBe('g1');
    expect(r1.items[39]?.id).toBe('g40');
    expect(r1.more).toBe(true);
    expect(r1.nextCursor).toEqual(at('g40'));
    const r2 = await fetch(makeCtx({ source, cursor: r1.nextCursor, routes }).ctx);
    expect(r2.items[0]?.id).toBe('g41');
    expect(r2.more).toBe(true);
    const r3 = await fetch(makeCtx({ source, cursor: r2.nextCursor, routes }).ctx);
    expect(r3.items).toHaveLength(15);
    expect(r3).toMatchObject({ more: false, nextCursor: at('g95', '"big"') });
  });

  it('fetch: warns when the cursor key is gone and treats every item as new', async () => {
    const h = makeCtx({ source, cursor: at('icsa-gone', '"f0"'), routes: [route(URL_, feedReply(xml))] });
    const r = await fetch(h.ctx);
    expect(r.items).toHaveLength(6);
    expect(h.logs.some((l) => l.msg.includes('cursor key is not in the feed'))).toBe(true);
  });

  it('honours order: oldest-first', async () => {
    const oldestFirst = { ...source, pull: { feed: { url: URL_, order: 'oldest-first' as const } } };
    const doc =
      '<rss><channel><item><guid>a</guid></item><item><guid>b</guid></item><item><guid>c</guid></item></channel></rss>';
    const h = makeCtx({ source: oldestFirst, cursor: at('a', '"x"'), routes: [route(URL_, feedReply(doc))] });
    const r = await fetch(h.ctx);
    expect(r.items.map((i) => i.id)).toEqual(['b', 'c']);
    expect(r.nextCursor?.value).toBe('c');
  });

  it('reads Atom (id) and RDF (rdf:about), and falls back to link', async () => {
    const atom = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>t</title>
      <entry><id>urn:1</id><title>One</title><link href="https://x.test/1"/><updated>2025-05-01T00:00:00Z</updated></entry>
      <entry><id>urn:0</id><title>Zero</title><link rel="alternate" href="https://x.test/0"/></entry></feed>`;
    const a = await fetch(makeCtx({ source, routes: [route(URL_, feedReply(atom))] }).ctx);
    expect(a.items.map((i) => i.id)).toEqual(['urn:0', 'urn:1']);
    const rdf = `<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/">
      <channel rdf:about="https://x.test/"><title>c</title></channel>
      <item rdf:about="https://x.test/a"><title>A</title><link>https://x.test/a</link></item>
      <item rdf:about="https://x.test/b"><title>B</title><link>https://x.test/b</link></item></rdf:RDF>`;
    const r = await fetch(makeCtx({ source, routes: [route(URL_, feedReply(rdf))] }).ctx);
    expect(r.items.map((i) => i.id)).toEqual(['https://x.test/b', 'https://x.test/a']);
    const noGuid =
      '<rss><channel><item><title>x</title><link>https://x.test/only</link></item></channel></rss>';
    const n = await fetch(makeCtx({ source, routes: [route(URL_, feedReply(noGuid))] }).ctx);
    expect(n.items[0]?.id).toBe('https://x.test/only');
  });

  it('rejects XML that declares an entity, as format', async () => {
    const evil =
      '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><rss><channel><item><guid>&a;</guid></item></channel></rss>';
    await expect(
      fetch(makeCtx({ source, routes: [route(URL_, feedReply(evil))] }).ctx),
    ).rejects.toMatchObject({
      code: 'format',
      retryable: false,
    });
  });

  it('rejects something that is not a feed, as format', async () => {
    await expect(
      fetch(makeCtx({ source, routes: [route(URL_, feedReply('<html/>'))] }).ctx),
    ).rejects.toMatchObject({ code: 'format' });
  });

  it('a link-only source (zdi) keeps { id, title, date, link } and no description anywhere', async () => {
    const zdi = {
      ...(SOURCE_BY_ID.get('zdi') as NonNullable<ReturnType<typeof SOURCE_BY_ID.get>>),
      pull: { feed: { url: 'https://www.zerodayinitiative.com/rss/published/' } },
    };
    const doc = `<rss><channel><item><title>ZDI-25-100: Example</title><link>https://www.zerodayinitiative.com/advisories/ZDI-25-100/</link>
      <guid>ZDI-25-100</guid><pubDate>Mon, 19 May 2025 00:00:00 GMT</pubDate>
      <description>SECRET-DESCRIPTION text we may not keep</description></item></channel></rss>`;
    const h = makeCtx({
      source: zdi,
      routes: [route('https://www.zerodayinitiative.com/rss/published/', feedReply(doc))],
    });
    const r = await fetch(h.ctx);
    expect(r.items[0]?.body).toEqual({
      id: 'ZDI-25-100',
      title: 'ZDI-25-100: Example',
      date: 'Mon, 19 May 2025 00:00:00 GMT',
      link: 'https://www.zerodayinitiative.com/advisories/ZDI-25-100/',
    } satisfies LinkOnlyItem);
    expect(JSON.stringify(r)).not.toContain('SECRET-DESCRIPTION');
    expect(String(r.receipt?.body)).not.toContain('description');
    expect(JSON.parse(String(r.receipt?.body).trim())).toMatchObject({
      body: expect.stringContaining('ZDI-25-100'),
    });
  });

  it('with heavy, a change is a job hand-off with no items', async () => {
    const heavy = { ...source, heavy: true };
    const h = makeCtx({ source: heavy, cursor: at(key(3), '"f0"'), routes: [route(URL_, feedReply(xml))] });
    const r = await fetch(h.ctx);
    expect(r.items).toEqual([]);
    expect(r.heavy).toMatchObject({ kind: 'big-file', url: URL_ });
    expect(r.nextCursor?.value).toBe(key(1));
  });
});
