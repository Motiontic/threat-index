import type { AdvisoryRecord } from '@ti/core/types';
import { SOURCE_BY_ID, SOURCES } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import type { ChangeItem } from '../../patterns/src/changelist';
import { fetch as changelistFetch } from '../../patterns/src/changelist';
import { makeCtx, reply, route } from '../../patterns/test/helpers';
import { loadParser } from '../src/load';

const src = (id: string) => {
  const s = SOURCE_BY_ID.get(id);
  if (!s) throw new Error(`no source ${id}`);
  return s;
};
const BASE = 'https://wid.cert-bund.de/.well-known/csaf/white/';

describe('cert sources', () => {
  it('cert-cc: feed with a parser', async () => {
    const s = src('cert-cc');
    expect(s.pattern).toBe('feed');
    expect(s.parser).toBe('cert-cc');
    expect(s.pull).toEqual({ feed: { url: 'https://kb.cert.org/vuls/atomfeed/' } });
    expect(typeof (await loadParser('cert-cc')).parse).toBe('function');
  });

  it('jvn: heavy first-load', async () => {
    const s = src('jvn');
    expect(s.pattern).toBe('heavy');
    expect(s.heavy).toBe(true);
    expect(s.parser).toBe('jvn');
    expect(s.pull).toEqual({
      heavy: { url: 'https://jvndb.jvn.jp/en/rss/jvndb.rdf' },
      jobKind: 'first-load',
    });
    expect(typeof (await loadParser('jvn')).parse).toBe('function');
  });

  it('bsi-cert-bund: changelist with a parser', async () => {
    const s = src('bsi-cert-bund');
    expect(s.pattern).toBe('changelist');
    expect(s.parser).toBe('cert-bund');
    expect(s.pull).toEqual({
      changelist: { listUrl: `${BASE}changes.csv`, timeColumn: 1, refColumn: 0, itemUrl: `${BASE}{ref}` },
    });
    expect(typeof (await loadParser('cert-bund')).parse).toBe('function');
  });

  it('cert-in stays unwired; every licence is still ask', () => {
    const s = src('cert-in');
    expect(s.parser).toBeUndefined();
    expect(s.pull).toBeUndefined();
    expect(s.pattern).toBe('page');
    for (const id of ['cert-cc', 'jvn', 'bsi-cert-bund', 'cert-in']) expect(src(id).licence).toBe('ask');
    expect(SOURCES.length).toBeGreaterThan(0);
  });

  it('bsi-cert-bund through the changelist pattern', async () => {
    const h = makeCtx({
      source: src('bsi-cert-bund'),
      cursor: { kind: 'timestamp', value: JSON.stringify(['2026-11-22T22:00:00+0000', 'a']), etag: '"v1"' },
      routes: [
        route(
          `${BASE}changes.csv`,
          reply(fixture('bsi-cert-bund', 'changes-head.csv'), 206, {
            'content-range': 'bytes 0-294/295',
            etag: '"v2"',
          }),
        ),
        route(
          new RegExp(`^${BASE.replace(/[.]/g, '\\.')}2026/wid-sec-w-2026-\\d+\\.json$`),
          reply(fixture('bsi-cert-bund', 'wid-sec-w-2026-4715.json'), 200, {
            'content-type': 'application/json',
          }),
        ),
      ],
    });
    const res = await changelistFetch(h.ctx);
    expect(res.items).toHaveLength(5);
    const { parse } = await loadParser('cert-bund');
    const recs: AdvisoryRecord[] = [];
    for (const item of res.items) {
      const out = parse(item.body as ChangeItem);
      recs.push(...((Array.isArray(out) ? out : out.records) as AdvisoryRecord[]));
    }
    expect(recs).toHaveLength(50);
    expect(recs[0]?.sourceId).toMatch(/^WID-SEC-W-2026-4715:CVE-/);
  });
});
