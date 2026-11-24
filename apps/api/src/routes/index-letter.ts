import type { IndexLetterResponse } from '@ti/core/api';
import { indexLetterKey, sitemapKey } from '@ti/core/r2-keys';
import { Hono } from 'hono';
import { cachedPublic, guarded } from '../lib/cache';
import type { AppEnv } from '../lib/env';

const route = new Hono<AppEnv>();

const INDEX_TTL = 600;
const PAGE = 500;
const MAX_PAGE_OBJECT_BYTES = 1024 * 1024;

function isIndexPage(v: unknown): v is IndexLetterResponse {
  if (typeof v !== 'object' || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.letter === 'string' &&
    Array.isArray(o.items) &&
    o.items.every(
      (i) =>
        typeof i === 'object' &&
        i !== null &&
        typeof (i as Record<string, unknown>).key === 'string' &&
        typeof (i as Record<string, unknown>).title === 'string',
    ) &&
    (o.cursor === undefined || typeof o.cursor === 'string')
  );
}

/** Key bands for a letter: upper and lower case, or digits (`0`–`:`, ':' is the char after '9'). */
function bands(letter: string): [string, string][] {
  if (letter === '0') return [['0', ':']];
  const lo = letter.toLowerCase();
  const up = letter.toUpperCase();
  const next = (ch: string) => String.fromCharCode(ch.charCodeAt(0) + 1);
  return [
    [up, next(up)],
    [lo, next(lo)],
  ];
}

// Public.
route.get('/v1/index/:letter', (c) =>
  guarded(c, 'GET /v1/index/:letter', async () => {
    const letter = c.req.param('letter').toLowerCase();
    if (!/^[a-z0]$/.test(letter)) return c.json({ error: 'bad_letter' }, 400);
    const cursor = c.req.query('cursor');
    if (cursor !== undefined && (cursor.length === 0 || cursor.length > 128))
      return c.json({ error: 'bad_cursor' }, 400);

    const path = `/v1/index/${letter}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`;
    return cachedPublic(c, INDEX_TTL, path, async () => {
      // `p<n>` is a page of the R2 index; anything else is a D1 key from the fallback below.
      const pageNo = cursor === undefined ? 0 : /^p(\d{1,6})$/.test(cursor) ? Number(cursor.slice(1)) : null;
      if (pageNo !== null) {
        const obj = await c.env.BUCKET.get(indexLetterKey(letter, pageNo));
        if (obj && obj.size <= MAX_PAGE_OBJECT_BYTES) {
          let parsed: unknown;
          try {
            parsed = await obj.json();
          } catch {
            parsed = null;
          }
          if (isIndexPage(parsed) && parsed.items.length <= PAGE) return c.json(parsed);
        }
        if (pageNo > 0) return c.json({ error: 'bad_cursor' }, 400); // the index was rebuilt since
      }
      const [b1, b2] = bands(letter);
      const params: unknown[] = [...(b1 ?? []), ...(b2 ?? [])];
      const ranges = [b1, b2]
        .filter((b): b is [string, string] => b !== undefined)
        .map((_, i) => `(key >= ?${2 * i + 1} AND key < ?${2 * i + 2})`)
        .join(' OR ');
      let sql = `SELECT key, title FROM vulns WHERE (${ranges})`;
      if (cursor) {
        params.push(cursor);
        sql += ` AND key > ?${params.length}`;
      }
      sql += ` ORDER BY key LIMIT ${PAGE + 1}`;
      const rows = (
        await c.env.DB_VULNS.prepare(sql)
          .bind(...params)
          .all<{ key: string; title: string }>()
      ).results;
      const items = rows.slice(0, PAGE).map((r) => ({ key: r.key, title: r.title }));
      const body: IndexLetterResponse = { letter, items };
      if (rows.length > PAGE) body.cursor = items[items.length - 1]?.key;
      return c.json(body);
    });
  }),
);

// Public. Streamed from R2; the web app proxies it.
route.get('/v1/sitemap.xml', (c) =>
  guarded(c, 'GET /v1/sitemap.xml', async () => {
    const obj = await c.env.BUCKET.get(sitemapKey());
    if (!obj) return c.json({ error: 'not_found' }, 404);
    return new Response(obj.body, {
      headers: { 'content-type': 'application/xml', 'cache-control': `public, max-age=${INDEX_TTL}` },
    });
  }),
);

export default route;
