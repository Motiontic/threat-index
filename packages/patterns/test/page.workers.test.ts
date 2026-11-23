import type { Cursor } from '@ti/core/types';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { check, fetch } from '../src/page';
import { sourceWith } from './examples';
import { makeCtx, reply, route } from './helpers';

const source = sourceWith('cert-in');
const URL_ = source.pull?.page?.url ?? '';
const html = fixture('cert-in', 'pattern-list.html');
const page = (body: string) => reply(body, 200, { etag: '"p1"', 'content-type': 'text/html' });
const at = (key: string, etag?: string): Cursor => ({
  kind: 'version',
  value: key,
  ...(etag ? { etag } : {}),
});

describe('page (Workers)', () => {
  it('fills fields, collapses text, makes href absolute and skips rows without a key', async () => {
    const h = makeCtx({ source, runId: 'r', routes: [route(URL_, page(html))] });
    const r = await fetch(h.ctx);
    expect(r.items.map((i) => i.id)).toEqual([
      'CIAD-2025-0037',
      'CIAD-2025-0038',
      'CIAD-2025-0039',
      'CIAD-2025-0040',
    ]);
    expect(r.items[3]?.body).toEqual({
      id: 'CIAD-2025-0040',
      title: 'Vulnerability 0 in Example',
      date: '20 May 2025',
      link: 'https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE=CIAD-2025-0040',
    });
    expect(r.nextCursor).toEqual(at('CIAD-2025-0040', '"p1"'));
    expect(r.more).toBe(false);
    expect(r.receipt).toMatchObject({ runId: 'r', contentType: 'application/x-ndjson' });
  });

  it('returns only new rows, oldest first; nothing new keeps the cursor', async () => {
    const h = makeCtx({ source, cursor: at('CIAD-2025-0038', '"p0"'), routes: [route(URL_, page(html))] });
    const r = await fetch(h.ctx);
    expect(r.items.map((i) => i.id)).toEqual(['CIAD-2025-0039', 'CIAD-2025-0040']);
    expect(r.nextCursor?.value).toBe('CIAD-2025-0040');
    const cur = at('CIAD-2025-0040', '"p0"');
    const same = makeCtx({ source, cursor: cur, routes: [route(URL_, page(html))] });
    expect(await fetch(same.ctx)).toMatchObject({ items: [], receipt: null, more: false, nextCursor: cur });
    expect(await check(makeCtx({ source, cursor: cur, routes: [route(URL_, page(html))] }).ctx)).toBe(
      'unchanged',
    );
    expect(
      await check(
        makeCtx({ source, cursor: at('CIAD-2025-0038', '"p0"'), routes: [route(URL_, page(html))] }).ctx,
      ),
    ).toBe('changed');
  });

  it('over 40 new rows gives 40 and more', async () => {
    const rows = Array.from(
      { length: 50 },
      (_, i) =>
        `<tr class="advisory"><td class="id">K-${100 - i}</td><td class="title"><a href="/a/${i}">t${i}</a></td><td class="date">d</td></tr>`,
    ).join('');
    const h = makeCtx({ source, routes: [route(URL_, page(`<table>${rows}</table>`))] });
    const r = await fetch(h.ctx);
    expect(r.items).toHaveLength(40);
    expect(r.more).toBe(true);
    expect(r.items[0]?.id).toBe('K-51');
    expect(r.nextCursor?.etag).toBeUndefined();
  });

  it('a link-only source cuts rows to { id, title, date, link } in items and receipt', async () => {
    const link = {
      ...(SOURCE_BY_ID.get('zdi') as NonNullable<ReturnType<typeof SOURCE_BY_ID.get>>),
      pull: { page: { ...source.pull?.page, fields: { ...source.pull?.page?.fields, summary: 'td.title' } } },
    } as typeof source;
    const doc = `<table><tr class="advisory"><td class="id">L-1</td><td class="title"><a href="/x">Hello</a></td><td class="date">1 May 2025</td></tr></table>`;
    const h = makeCtx({ source: link, routes: [route(URL_, page(doc))] });
    const r = await fetch(h.ctx);
    expect(r.items[0]?.body).toEqual({
      id: 'L-1',
      title: 'Hello',
      date: '1 May 2025',
      link: 'https://www.cert-in.org.in/x',
    });
    expect(String(r.receipt?.body)).not.toContain('summary');
    expect(String(r.receipt?.body)).not.toContain('<table');
  });

  it.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'data:text/html,hi',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
    'ftp://example.test/x',
  ])('drops a %s link, logs only the source id, keeps http(s) and relative ones', async (bad) => {
    const doc = `<table>
      <tr class="advisory"><td class="id">B-1</td><td class="title"><a href="${bad}">bad</a></td><td class="date">d</td></tr>
      <tr class="advisory"><td class="id">B-2</td><td class="title"><a href="/ok">ok</a></td><td class="date">d</td></tr>
      <tr class="advisory"><td class="id">B-3</td><td class="title"><a href="http://example.test/p">ok</a></td><td class="date">d</td></tr></table>`;
    const h = makeCtx({ source, routes: [route(URL_, page(doc))] });
    const r = await fetch(h.ctx);
    const links = Object.fromEntries(r.items.map((i) => [i.id, (i.body as { link?: string }).link]));
    expect(links['B-1']).toBeUndefined();
    expect(links['B-2']).toBe('https://www.cert-in.org.in/ok');
    expect(links['B-3']).toBe('http://example.test/p');
    const dropped = h.logs.filter((l) => l.msg.includes('dropped a link'));
    expect(dropped).toHaveLength(1);
    expect(dropped[0]?.extra).toEqual({ source: 'cert-in' });
  });

  it('with heavy, a change is a job hand-off', async () => {
    const heavy = { ...source, heavy: true };
    const r = await fetch(
      makeCtx({ source: heavy, cursor: at('CIAD-2025-0038', '"p0"'), routes: [route(URL_, page(html))] }).ctx,
    );
    expect(r.items).toEqual([]);
    expect(r.heavy).toMatchObject({ kind: 'big-file', url: URL_ });
  });
});
