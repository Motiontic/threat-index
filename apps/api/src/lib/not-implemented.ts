import type { Context } from 'hono';

/** Handler for routes whose feature has not landed yet. Auth is enforced before it runs. */
export const notImplemented = (c: Context) => c.json({ error: 'not_implemented' }, 501);
