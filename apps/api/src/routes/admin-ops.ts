import { getAuth } from '@hono/clerk-auth';
import { logEvent } from '@ti/core/log';
import { isAdmin, parseAdminIds } from '@ti/core/ops';
import { Hono } from 'hono';
import type { AppEnv } from '../lib/env';
import { buildOpsReport } from '../lib/ops';

const route = new Hono<AppEnv>();

// Anonymous and non-admin callers get the same 403, so the route does not reveal who is an admin.
route.get('/v1/admin/ops', async (c) => {
  c.header('Cache-Control', 'private, no-store');
  // An MCP identity never carries admin rights, even for a user in ADMIN_USER_IDS. This reads the Clerk
  // session directly (not currentUserId), and refuses an MCP call outright as a second guard.
  const userId = c.get('mcp') ? undefined : (getAuth(c)?.userId ?? undefined);
  if (!isAdmin(parseAdminIds(c.env.ADMIN_USER_IDS), userId)) return c.json({ error: 'forbidden' }, 403);
  logEvent('info', 'admin_ops_viewed', { requestId: c.get('requestId'), userId });
  try {
    return c.json(await buildOpsReport(c.env, new Date()));
  } catch (err) {
    logEvent('error', 'admin_ops_failed', { requestId: c.get('requestId'), name: (err as Error).name });
    return c.json({ error: 'internal', requestId: c.get('requestId') }, 500);
  }
});

export default route;
