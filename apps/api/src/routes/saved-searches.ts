import {
  MAX_SAVED_SEARCH_NAME_CHARS,
  MAX_SAVED_SEARCHES,
  type SavedSearchListResponse,
  type SavedSearchParams,
} from '@ti/core/account';
import { Hono } from 'hono';
import { z } from 'zod';
import {
  errorResponse,
  HttpError,
  noStore,
  parseBody,
  type SavedSearchRow,
  toSavedSearch,
} from '../lib/account';
import { requireUser } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { MAX_QUERY_CHARS, parseSearchParams } from '../lib/search-params';

const route = new Hono<AppEnv>();
route.use('/v1/me/saved-searches', noStore);
route.use('/v1/me/saved-searches/*', noStore);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const values = z.array(z.string().max(32)).max(12);
const Params = z
  .object({
    type: values.optional(),
    sig: values.optional(),
    sev: values.optional(),
    year: values.optional(),
    sort: z.enum(['rel', 'new']).optional(),
  })
  .strict();
const CreateBody = z
  .object({
    name: z.string().trim().min(1).max(MAX_SAVED_SEARCH_NAME_CHARS),
    query: z.string().trim().max(MAX_QUERY_CHARS),
    params: Params.optional(),
    alertsOn: z.boolean().optional(),
  })
  .strict();

const COLUMNS = 'id, label, query, params, alerts_on, created_at';

route.get('/v1/me/saved-searches', requireUser, async (c) => {
  const { results } = await c.env.DB_USERS.prepare(
    `SELECT ${COLUMNS} FROM saved_searches WHERE user_id = ?1 ORDER BY created_at DESC, id LIMIT ?2`,
  )
    .bind(c.get('userId'), MAX_SAVED_SEARCHES)
    .all<SavedSearchRow>();
  const res: SavedSearchListResponse = { items: results.map(toSavedSearch), limit: MAX_SAVED_SEARCHES };
  return c.json(res);
});

route.post('/v1/me/saved-searches', requireUser, async (c) => {
  try {
    const userId = c.get('userId');
    const body = await parseBody(c, CreateBody);
    const params: SavedSearchParams = body.params ?? {};
    const sp = new URLSearchParams();
    if (body.query) sp.set('q', body.query);
    for (const k of ['type', 'sig', 'sev', 'year'] as const) for (const v of params[k] ?? []) sp.append(k, v);
    if (params.sort) sp.set('sort', params.sort);
    if (!parseSearchParams(sp).ok) throw new HttpError(400, 'bad_request');

    const stored: SavedSearchParams = {};
    for (const k of ['type', 'sig', 'sev', 'year'] as const) if (params[k]) stored[k] = params[k];
    if (params.sort) stored.sort = params.sort;

    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    const inserted = await c.env.DB_USERS.prepare(
      `INSERT INTO saved_searches (user_id, id, label, query, created_at, params, alerts_on)
       SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE (SELECT COUNT(*) FROM saved_searches WHERE user_id = ?1) < ?8`,
    )
      .bind(
        userId,
        id,
        body.name,
        body.query,
        createdAt,
        JSON.stringify(stored),
        body.alertsOn ? 1 : 0,
        MAX_SAVED_SEARCHES,
      )
      .run();
    if ((inserted.meta.changes ?? 0) === 0) throw new HttpError(409, 'limit_reached');
    return c.json(
      toSavedSearch({
        id,
        label: body.name,
        query: body.query,
        params: JSON.stringify(stored),
        alerts_on: body.alertsOn ? 1 : 0,
        created_at: createdAt,
      }),
      201,
    );
  } catch (err) {
    return errorResponse(c, err);
  }
});

route.delete('/v1/me/saved-searches/:id', requireUser, async (c) => {
  const id = c.req.param('id');
  if (!UUID.test(id)) return c.json({ error: 'bad_id' }, 400);
  const res = await c.env.DB_USERS.prepare('DELETE FROM saved_searches WHERE user_id = ?1 AND id = ?2')
    .bind(c.get('userId'), id)
    .run();
  if ((res.meta.changes ?? 0) === 0) return c.json({ error: 'not_found' }, 404);
  return c.json({ ok: true });
});

export default route;
