import { type DeleteAccountResponse, MAX_DISPLAY_NAME_CHARS, type MePatch } from '@ti/core/account';
import { Hono } from 'hono';
import { z } from 'zod';
import {
  errorResponse,
  HttpError,
  loadOrCreateUser,
  noStore,
  parseBody,
  toMe,
  USER_COLUMNS,
  type UserRow,
} from '../lib/account';
import { requireUser } from '../lib/auth';
import { deleteClerkUser } from '../lib/clerk-api';
import { deleteUserData } from '../lib/delete-user';
import type { AppEnv } from '../lib/env';
import { eventAfterChange, mcpOf } from '../lib/watch-events';

const route = new Hono<AppEnv>();
route.use('/v1/me', noStore);

// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

const PatchBody = z
  .object({
    displayName: z
      .string()
      .trim()
      .min(1)
      .max(MAX_DISPLAY_NAME_CHARS)
      .refine((s) => !CONTROL.test(s))
      .nullable()
      .optional(),
    alerts: z
      .object({
        instant: z.boolean().optional(),
        digest: z.enum(['daily', 'weekly', 'off']).optional(),
        digestWeekday: z.number().int().min(0).max(6).optional(),
      })
      .strict()
      .optional(),
  })
  .strict()
  .refine(
    (b) => b.displayName !== undefined || (b.alerts && Object.values(b.alerts).some((v) => v !== undefined)),
  );

const McpPatch = z.object({ alerts: z.object({ digest: z.enum(['daily', 'weekly']) }).strict() }).strict();

// Signed in.
route.get('/v1/me', requireUser, async (c) => {
  try {
    return c.json(toMe(await loadOrCreateUser(c.env, c.get('userId'))));
  } catch (err) {
    return errorResponse(c, err);
  }
});

route.patch('/v1/me', requireUser, async (c) => {
  try {
    const userId = c.get('userId');
    const mcp = mcpOf(c);
    if (mcp) {
      // An MCP caller can only turn an alert digest on, and only while it is off.
      const raw = await parseBody(c, z.unknown());
      const asked = McpPatch.safeParse(raw);
      if (!asked.success) throw new HttpError(403, 'not_allowed_for_mcp');
      await loadOrCreateUser(c.env, userId);
      const [res] = await c.env.DB_USERS.batch([
        c.env.DB_USERS.prepare("UPDATE users SET digest = ?2 WHERE id = ?1 AND digest = 'off'").bind(
          userId,
          asked.data.alerts.digest,
        ),
        eventAfterChange(c.env.DB_USERS, mcp, 'digest_on', 'settings'),
      ]);
      if ((res?.meta.changes ?? 0) === 0) throw new HttpError(403, 'not_allowed_for_mcp');
      const now = await c.env.DB_USERS.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?1`)
        .bind(userId)
        .first<UserRow>();
      if (!now) return c.json({ error: 'sign_in_required' }, 401);
      return c.json(toMe(now));
    }
    const body: MePatch = await parseBody(c, PatchBody);
    await loadOrCreateUser(c.env, userId);
    const sets: string[] = [];
    const values: (string | number | null)[] = [];
    const set = (column: string, value: string | number | null) => {
      values.push(value);
      sets.push(`${column} = ?${values.length + 1}`);
    };
    if (body.displayName !== undefined) set('display_name', body.displayName);
    if (body.alerts?.instant !== undefined) set('alert_instant', body.alerts.instant ? 1 : 0);
    if (body.alerts?.digest !== undefined) set('digest', body.alerts.digest);
    if (body.alerts?.digestWeekday !== undefined) set('digest_weekday', body.alerts.digestWeekday);
    await c.env.DB_USERS.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?1`)
      .bind(userId, ...values)
      .run();
    const row = await c.env.DB_USERS.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?1`)
      .bind(userId)
      .first<UserRow>();
    if (!row) return c.json({ error: 'sign_in_required' }, 401);
    return c.json(toMe(row));
  } catch (err) {
    return errorResponse(c, err);
  }
});

// Our rows go first, so a Clerk failure leaves nothing of ours behind and a retry is safe.
route.delete('/v1/me', requireUser, async (c) => {
  const userId = c.get('userId');
  await deleteUserData(c.env.DB_USERS, userId);
  try {
    await deleteClerkUser(c.env.CLERK_SECRET_KEY, userId);
  } catch {
    return c.json({ error: 'clerk_delete_failed' }, 502);
  }
  const res: DeleteAccountResponse = { deleted: true };
  return c.json(res);
});

export default route;
