import { canonicalEcosystem, normaliseName } from '@ti/core/packages';
import { Hono } from 'hono';
import { z } from 'zod';
import { errorResponse, HttpError, noStore, parseBody } from '../lib/account';
import { requireUser } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import {
  eventAfterChange,
  mcpOf,
  removalCapSql,
  removalCut,
  removalLimitResponse,
} from '../lib/watch-events';

/** Most package watches one user can have. */
export const MAX_WATCH_PACKAGES = 200;
const MAX_NAME_CHARS = 214;

const route = new Hono<AppEnv>();
route.use('/v1/me/watch/packages', noStore);
route.use('/v1/me/watch/packages/*', noStore);

const PutBody = z.object({ alertsOn: z.boolean().optional() }).strict();

interface Row {
  ecosystem: string;
  name: string;
  created_at: string;
  alerts_on: number;
}

/** `c.req.param()` already decoded the segment once: no second decode. */
function target(raw: { ecosystem: string; name: string }): { ecosystem: string; name: string } {
  const ecosystem = canonicalEcosystem(raw.ecosystem);
  const name = ecosystem ? normaliseName(ecosystem, raw.name) : null;
  if (!ecosystem || !name || name.length > MAX_NAME_CHARS) throw new HttpError(400, 'invalid_argument');
  return { ecosystem, name };
}

route.get('/v1/me/watch/packages', requireUser, async (c) => {
  const { results } = await c.env.DB_USERS.prepare(
    'SELECT ecosystem, name, created_at, alerts_on FROM watch_packages WHERE user_id = ?1 ORDER BY created_at DESC, ecosystem, name LIMIT ?2',
  )
    .bind(c.get('userId'), MAX_WATCH_PACKAGES)
    .all<Row>();
  return c.json({
    items: results.map((r) => ({
      ecosystem: r.ecosystem,
      name: r.name,
      createdAt: r.created_at,
      alertsOn: r.alerts_on === 1,
    })),
    limit: MAX_WATCH_PACKAGES,
  });
});

route.put('/v1/me/watch/packages/:ecosystem/:name', requireUser, async (c) => {
  try {
    const userId = c.get('userId');
    const mcp = mcpOf(c);
    const { ecosystem, name } = target(c.req.param());
    const body = await parseBody(c, PutBody, { optional: true });
    // An MCP caller may turn alerts on, never off: a stolen token must not silence them.
    if (mcp && body.alertsOn === false) throw new HttpError(403, 'not_allowed_for_mcp');
    const db = c.env.DB_USERS;
    const label = `pkg:${ecosystem}/${name}`;
    // Only a package MTI has records for can be watched. An OS ecosystem (`Debian`) also matches `Debian:12`.
    const known = await c.env.DB_ADVISORIES.prepare(
      `SELECT 1 AS x FROM affected WHERE name = ?2 AND (ecosystem = ?1 OR (ecosystem >= ?1 || ':' AND ecosystem < ?1 || ';')) LIMIT 1`,
    )
      .bind(ecosystem, name)
      .first();
    if (!known) throw new HttpError(404, 'unknown_package');

    const stmts = [
      db
        .prepare(
          `INSERT INTO watch_packages (user_id, ecosystem, name, created_at, alerts_on)
           SELECT ?1, ?2, ?3, ?4, ?5 WHERE (SELECT COUNT(*) FROM watch_packages WHERE user_id = ?1) < ?6
           ON CONFLICT(user_id, ecosystem, name) DO NOTHING`,
        )
        .bind(
          userId,
          ecosystem,
          name,
          new Date().toISOString(),
          body.alertsOn === false ? 0 : 1,
          MAX_WATCH_PACKAGES,
        ),
    ];
    if (mcp) stmts.push(eventAfterChange(db, mcp, 'add', label));
    if (body.alertsOn !== undefined) {
      stmts.push(
        db
          .prepare(
            'UPDATE watch_packages SET alerts_on = ?4 WHERE user_id = ?1 AND ecosystem = ?2 AND name = ?3 AND alerts_on != ?4',
          )
          .bind(userId, ecosystem, name, body.alertsOn ? 1 : 0),
      );
      if (mcp) stmts.push(eventAfterChange(db, mcp, 'alerts_on', label));
    }
    const results = await db.batch(stmts);
    const created = (results[0]?.meta.changes ?? 0) > 0;
    if (!created) {
      const exists = await db
        .prepare('SELECT 1 AS x FROM watch_packages WHERE user_id = ?1 AND ecosystem = ?2 AND name = ?3')
        .bind(userId, ecosystem, name)
        .first();
      if (!exists) throw new HttpError(409, 'limit_reached');
    }
    return c.json({ created });
  } catch (err) {
    return errorResponse(c, err);
  }
});

route.delete('/v1/me/watch/packages/:ecosystem/:name', requireUser, async (c) => {
  try {
    const userId = c.get('userId');
    const mcp = mcpOf(c);
    const { ecosystem, name } = target(c.req.param());
    const db = c.env.DB_USERS;
    const del = db.prepare(
      `DELETE FROM watch_packages WHERE user_id = ?1 AND ecosystem = ?2 AND name = ?3${
        mcp ? ` AND ${removalCapSql('?4')}` : ''
      }`,
    );
    const stmts = [mcp ? del.bind(userId, ecosystem, name, removalCut()) : del.bind(userId, ecosystem, name)];
    if (mcp) stmts.push(eventAfterChange(db, mcp, 'remove', `pkg:${ecosystem}/${name}`));
    const removed = ((await db.batch(stmts))[0]?.meta.changes ?? 0) > 0;
    if (!removed && mcp) {
      const exists = await db
        .prepare('SELECT 1 AS x FROM watch_packages WHERE user_id = ?1 AND ecosystem = ?2 AND name = ?3')
        .bind(userId, ecosystem, name)
        .first();
      if (exists) return removalLimitResponse(c, userId);
    }
    return c.json({ removed });
  } catch (err) {
    return errorResponse(c, err);
  }
});

export default route;
