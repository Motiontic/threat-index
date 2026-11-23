import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { fetch } from '../src/page';
import { makeCtx, reply, route } from './helpers';

const check = async (id: string, dir: string, html: string, rowsFile: string, take: number) => {
  const source = SOURCE_BY_ID.get(id);
  const url = source?.pull?.page?.url;
  if (!source || !url) throw new Error(`no page pull for ${id}`);
  const h = makeCtx({
    source,
    routes: [route(url, reply(fixture(dir, html), 200, { 'content-type': 'text/html' }))],
  });
  const r = await fetch(h.ctx);
  const want = (JSON.parse(fixture(dir, rowsFile)) as Record<string, string>[]).slice(0, take);
  // The pattern yields oldest first; the page is newest first.
  expect(r.items.map((i) => i.body).reverse()).toEqual(want);
};

describe('page pattern on the real US breach markup', () => {
  it('hhs-ocr: the PrimeFaces table gives the rows in rows.json', async () => {
    await check('hhs-ocr', 'hhs-ocr', 'listing.html', 'rows.json', 3);
  });
  it('ca-ag: the Drupal views table gives the rows in rows.json', async () => {
    await check('ca-ag', 'ca-ag', 'list.html', 'rows.json', 5);
  });
});
