import type {
  AlertSettings,
  DigestCadence,
  Me,
  SavedSearch,
  SavedSearchParams,
  WatchItem,
} from '@ti/core/account';
import type { Context, MiddlewareHandler } from 'hono';
import type { z } from 'zod';
import { getClerkUser } from './clerk-api';
import type { AppEnv, Bindings } from './env';

/** A row of `users`, the columns the account routes use. */
export interface UserRow {
  id: string;
  email: string;
  name: string | null;
  display_name: string | null;
  alert_instant: number;
  digest: string;
  digest_weekday: number;
}
/** A row of `watch`. */
export interface WatchRow {
  entry_key: string;
  alerts_on: number;
  created_at: string;
}
/** A row of `saved_searches`. */
export interface SavedSearchRow {
  id: string;
  label: string;
  query: string;
  params: string;
  alerts_on: number;
  created_at: string;
}

export const USER_COLUMNS = 'id, email, name, display_name, alert_instant, digest, digest_weekday';
export const MAX_BODY_BYTES = 4096;

/** An error response the routes throw-and-catch style: `{ error }` with a status. */
export class HttpError extends Error {
  constructor(
    readonly status: 400 | 401 | 404 | 409 | 502,
    readonly code: string,
  ) {
    super(code);
  }
}

/** Marks every response of the route as private. Register on `/v1/me` and `/v1/me/*`. */
export const noStore: MiddlewareHandler<AppEnv> = async (c, next) => {
  await next();
  c.header('cache-control', 'private, no-store');
};

/** Maps an `HttpError` to its `{ error }` response; rethrows anything else. */
export function errorResponse(c: Context, err: unknown): Response {
  if (err instanceof HttpError) return c.json({ error: err.code }, err.status);
  throw err;
}

/** Parses the JSON body with a strict schema. Not JSON, over 4 KB, or invalid → 400 `bad_request`. */
export async function parseBody<S extends z.ZodType>(
  c: Context,
  schema: S,
  opts: { optional?: boolean } = {},
): Promise<z.infer<S>> {
  const declared = Number(c.req.header('content-length') ?? 0);
  if (declared > MAX_BODY_BYTES) throw new HttpError(400, 'bad_request');
  const text = await c.req.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) throw new HttpError(400, 'bad_request');
  let value: unknown;
  if (opts.optional && text.trim() === '') value = {};
  else {
    try {
      value = JSON.parse(text);
    } catch {
      throw new HttpError(400, 'bad_request');
    }
  }
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new HttpError(400, 'bad_request');
  return parsed.data;
}

/** Maps a `users` row to `Me`. */
export function toMe(row: UserRow): Me {
  const alerts: AlertSettings = {
    instant: row.alert_instant === 1,
    digest: row.digest as DigestCadence,
    digestWeekday: row.digest_weekday,
  };
  return { userId: row.id, email: row.email, displayName: row.display_name ?? row.name ?? null, alerts };
}

/** Maps a `watch` row and its title to a `WatchItem`. */
export function toWatchItem(row: WatchRow, title: string): WatchItem {
  return { entryKey: row.entry_key, title, alertsOn: row.alerts_on === 1, createdAt: row.created_at };
}

/** Maps a `saved_searches` row to a `SavedSearch`. */
export function toSavedSearch(row: SavedSearchRow): SavedSearch {
  let params: SavedSearchParams = {};
  try {
    params = JSON.parse(row.params) as SavedSearchParams;
  } catch {
    // keep {}
  }
  return {
    id: row.id,
    name: row.label,
    query: row.query,
    params,
    alertsOn: row.alerts_on === 1,
    createdAt: row.created_at,
  };
}

/**
 * The user's row. When it is missing (the webhook has not arrived yet) it is created from Clerk.
 * Clerk has no such user → 401; Clerk fails → 502.
 */
export async function loadOrCreateUser(
  env: Pick<Bindings, 'DB_USERS' | 'CLERK_SECRET_KEY'>,
  userId: string,
): Promise<UserRow> {
  const select = () =>
    env.DB_USERS.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?1`).bind(userId).first<UserRow>();
  const existing = await select();
  if (existing) return existing;

  let clerk: Awaited<ReturnType<typeof getClerkUser>>;
  try {
    clerk = await getClerkUser(env.CLERK_SECRET_KEY, userId);
  } catch {
    throw new HttpError(502, 'clerk_unavailable');
  }
  if (!clerk) throw new HttpError(401, 'sign_in_required');
  await env.DB_USERS.prepare(
    `INSERT INTO users (id, email, name, created_at, digest_weekday) VALUES (?1, ?2, ?3, ?4, ?5)
     ON CONFLICT(id) DO NOTHING`,
  )
    .bind(userId, clerk.email, clerk.name, new Date().toISOString(), new Date().getUTCDay())
    .run();
  const created = await select();
  if (!created) throw new HttpError(502, 'clerk_unavailable');
  return created;
}

/** Titles for vuln keys, read in chunks of 100 in one batch. A key with no row maps to itself. */
export async function titlesFor(
  env: Pick<Bindings, 'DB_VULNS'>,
  keys: string[],
): Promise<Map<string, string>> {
  const titles = new Map<string, string>(keys.map((k) => [k, k]));
  if (keys.length === 0) return titles;
  const stmts: D1PreparedStatement[] = [];
  for (let i = 0; i < keys.length; i += 100) {
    const chunk = keys.slice(i, i + 100);
    stmts.push(
      env.DB_VULNS.prepare(
        `SELECT key, title FROM vulns WHERE key IN (${chunk.map(() => '?').join(',')})`,
      ).bind(...chunk),
    );
  }
  for (const r of await env.DB_VULNS.batch<{ key: string; title: string }>(stmts)) {
    for (const row of r.results) if (row.title) titles.set(row.key, row.title);
  }
  return titles;
}
