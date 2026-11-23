import type { Cursor } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { parseKev } from '../../parsers/src/kev';
import { check, fetch, MAX_FINGERPRINT_ITEMS } from '../src/fingerprint';
import { EXAMPLES, sourceWith } from './examples';
import { makeCtx, ranged, reply, route } from './helpers';

const URL_ = EXAMPLES['cisa-kev'].fingerprint.url;
const source = sourceWith('cisa-kev');
const v1 = fixture('cisa-kev', 'sample.json');
const v2 = fixture('cisa-kev', 'pattern-catalog-v2.json');

const state = (c: Cursor) => JSON.parse(c.value) as { v: string | null; h: Record<string, string> };

function catalogue(n: number, version = '2025.06.01'): string {
  return JSON.stringify({
    catalogVersion: version,
    vulnerabilities: Array.from({ length: n }, (_, i) => ({ cveID: `CVE-2025-${10000 + i}`, n: i })),
  });
}

/** The cursor a first run over `text` ends with. */
async function settle(text: string, validator = '"e1"'): Promise<Cursor> {
  const h = makeCtx({ source, routes: [route(URL_, ranged(text, { etag: validator }))] });
  return (await fetch(h.ctx)).nextCursor;
}

describe('fingerprint', () => {
  it('fetch with a null cursor does the first run in the Worker, and bodies parse with the KEV parser', async () => {
    const h = makeCtx({ source, runId: 'r', routes: [route(URL_, ranged(v1, { etag: '"e1"' }))] });
    const r = await fetch(h.ctx);
    expect(r.heavy).toBeUndefined();
    expect(r.items.map((i) => i.id)).toEqual(['CVE-2025-3248']);
    const parsed = parseKev(r.items[0]?.body);
    expect(parsed.records[0]).toMatchObject({ vulnKey: 'CVE-2025-3248', kind: 'exploited_wild' });
    expect(r.nextCursor).toMatchObject({ kind: 'version', etag: '"e1"' });
    expect(state(r.nextCursor).v).toBe('2025.05.05');
    expect(Object.keys(state(r.nextCursor).h)).toEqual(['CVE-2025-3248']);
    expect(state(r.nextCursor).h['CVE-2025-3248']).toMatch(/^[0-9a-f]{8}$/);
    expect(r).toMatchObject({ more: false, receipt: { runId: 'r', contentType: 'application/x-ndjson' } });
  });

  it('check: the version in the first bytes against the stored one', async () => {
    const cur = await settle(v1);
    const same = makeCtx({ source, cursor: cur, routes: [route(URL_, ranged(v1))] });
    expect(await check(same.ctx)).toBe('unchanged');
    expect(same.requests[0]?.headers.range).toBe('bytes=0-511');
    const newer = makeCtx({ source, cursor: cur, routes: [route(URL_, ranged(v2))] });
    expect(await check(newer.ctx)).toBe('changed');
    expect(await check(makeCtx({ source }).ctx)).toBe('changed');
  });

  it('fetch with nothing new keeps the cursor and returns no receipt', async () => {
    const cur = await settle(v1);
    const h = makeCtx({ source, cursor: cur, routes: [route(URL_, ranged(v1, { etag: '"e1"' }))] });
    expect(await fetch(h.ctx)).toMatchObject({ items: [], receipt: null, more: false, nextCursor: cur });
  });

  it('fetch: a later catalogue returns only changed and new entries', async () => {
    const cur = await settle(v1);
    const h = makeCtx({ source, cursor: cur, routes: [route(URL_, ranged(v2, { etag: '"e2"' }))] });
    const r = await fetch(h.ctx);
    expect(r.items.map((i) => i.id)).toEqual(['CVE-2025-3248', 'CVE-2025-4000']);
    const parsed = r.items.map((i) => parseKev(i.body));
    expect(parsed.map((p) => p.catalogVersion)).toEqual(['2025.05.12', '2025.05.12']);
    expect(parsed[1]?.records.map((x) => x.kind)).toEqual(['exploited_wild', 'ransomware']);
    expect(state(r.nextCursor).v).toBe('2025.05.12');
    expect(Object.keys(state(r.nextCursor).h)).toHaveLength(2);
    expect(r.nextCursor.etag).toBe('"e2"');
    // The same file again: nothing is new.
    const again = makeCtx({
      source,
      cursor: r.nextCursor,
      routes: [route(URL_, ranged(v2, { etag: '"e2"' }))],
    });
    expect((await fetch(again.ctx)).items).toEqual([]);
  });

  it('fetch: a removed key just leaves the cursor', async () => {
    const two = await settle(v2);
    const doc = JSON.parse(v2) as { vulnerabilities: unknown[] };
    doc.vulnerabilities.pop(); // CVE-2025-4000 is gone; CVE-2025-3248 is as in v2
    const h = makeCtx({
      source,
      cursor: two,
      routes: [route(URL_, ranged(JSON.stringify(doc), { etag: '"e3"' }))],
    });
    const r = await fetch(h.ctx);
    expect(r.items).toEqual([]);
    expect(Object.keys(state(r.nextCursor).h)).toEqual(['CVE-2025-3248']);
    expect(state(r.nextCursor).v).toBe('2025.05.12');
  });

  it('fetch: over 40 changed gives 40 and more with v null, then the rest, in file order', async () => {
    const text = catalogue(85);
    const routes = [route(URL_, ranged(text, { etag: '"big"' }))];
    const r1 = await fetch(makeCtx({ source, routes }).ctx);
    expect(r1.items).toHaveLength(40);
    expect(r1.more).toBe(true);
    expect(state(r1.nextCursor).v).toBeNull();
    expect(r1.nextCursor.etag).toBeUndefined();
    expect(Object.keys(state(r1.nextCursor).h)).toHaveLength(40);

    const h2 = makeCtx({ source, cursor: r1.nextCursor, routes });
    expect(await check(h2.ctx)).toBe('changed');
    expect(h2.requests).toHaveLength(0);
    const r2 = await fetch(h2.ctx);
    expect(r2.items.map((i) => i.id)[0]).toBe('CVE-2025-10040');
    expect(r2.items).toHaveLength(40);
    const r3 = await fetch(makeCtx({ source, cursor: r2.nextCursor, routes }).ctx);
    expect(r3.items).toHaveLength(5);
    expect(r3.more).toBe(false);
    expect(state(r3.nextCursor)).toMatchObject({ v: '2025.06.01' });
    expect(r3.nextCursor.etag).toBe('"big"');
  });

  it('fetch: over MAX_FINGERPRINT_ITEMS entries, or a file over the size limit, is a big-file hand-off', async () => {
    const huge = makeCtx({ source, routes: [route(URL_, ranged(catalogue(MAX_FINGERPRINT_ITEMS + 1)))] });
    const r = await fetch(huge.ctx);
    expect(r.items).toEqual([]);
    expect(r.heavy).toMatchObject({ kind: 'big-file', url: URL_, sourceId: 'cisa-kev' });
    const big = makeCtx({
      source,
      routes: [route(URL_, reply('x', 200, { 'content-length': String(9 * 1024 * 1024) }))],
    });
    expect((await fetch(big.ctx)).heavy?.kind).toBe('big-file');
  });

  it('without a version, check uses HEAD and the validator', async () => {
    const plain = {
      ...source,
      pull: { fingerprint: { ...EXAMPLES['cisa-kev'].fingerprint, version: undefined } },
    };
    const cur = await (async () => {
      const h = makeCtx({ source: plain, routes: [route(URL_, ranged(v1, { etag: '"e1"' }))] });
      return (await fetch(h.ctx)).nextCursor;
    })();
    expect(cur.kind).toBe('etag');
    expect(state(cur).v).toBe('"e1"');
    const a = makeCtx({ source: plain, cursor: cur, routes: [route(URL_, reply(null, 304), 'HEAD')] });
    expect(await check(a.ctx)).toBe('unchanged');
    expect(a.requests[0]?.headers['if-none-match']).toBe('"e1"');
    const b = makeCtx({
      source: plain,
      cursor: cur,
      routes: [route(URL_, reply(null, 200, { etag: '"e2"' }), 'HEAD')],
    });
    expect(await check(b.ctx)).toBe('changed');
  });

  it('reads a CSV: entries are { header: value } keyed by a column', async () => {
    const csvSource = {
      ...source,
      pull: { fingerprint: { url: 'https://example.test/list.csv', format: 'csv' as const, key: 'id' } },
    };
    const text = 'id,name\n1,"A, Inc"\n2,B\n';
    const h = makeCtx({
      source: csvSource,
      routes: [route('https://example.test/list.csv', ranged(text, { etag: '"c"' }))],
    });
    const r = await fetch(h.ctx);
    expect(r.items).toEqual([
      { id: '1', body: { id: '1', name: 'A, Inc' } },
      { id: '2', body: { id: '2', name: 'B' } },
    ]);
    const changed = makeCtx({
      source: csvSource,
      cursor: r.nextCursor,
      routes: [
        route('https://example.test/list.csv', ranged('id,name\n1,"A, Inc"\n2,C\n3,D\n', { etag: '"c2"' })),
      ],
    });
    expect((await fetch(changed.ctx)).items.map((i) => i.id)).toEqual(['2', '3']);
  });

  it('with heavy, a change is a job hand-off and nothing is parsed', async () => {
    const heavy = { ...source, heavy: true };
    const cur = await settle(v1);
    const h = makeCtx({ source: heavy, cursor: cur, routes: [route(URL_, ranged(v2))] });
    const r = await fetch(h.ctx);
    expect(r.items).toEqual([]);
    expect(r.heavy).toMatchObject({ kind: 'big-file', reason: '2025.05.05 → 2025.05.12' });
    expect(state(r.nextCursor).v).toBe('2025.05.12');
  });
});
