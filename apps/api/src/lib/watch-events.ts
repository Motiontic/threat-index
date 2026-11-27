import type { McpIdentity } from '@ti/core/mcp-user';
import type { Context } from 'hono';
import type { AppEnv } from './env';

/** Most watches (entry and package together) an MCP caller may remove in any 24 hours. */
export const MCP_REMOVAL_CAP = 20;
const DAY_MS = 86_400_000;

/** Host of an https `client_id` URL, or null. Shown to the user as self-reported. */
export function clientHost(clientId: string): string | null {
  try {
    const u = new URL(clientId);
    return u.protocol === 'https:' ? u.host.slice(0, 100) : null;
  } catch {
    return null;
  }
}

/** The signed MCP identity of this request, or undefined for the website. */
export const mcpOf = (c: Context<AppEnv>): McpIdentity | undefined => c.get('mcp');

/**
 * An INSERT of one `watch_events` row that runs only if the statement before it in the same batch changed
 * a row (`changes() > 0`). Put it right after the change it records.
 */
export function eventAfterChange(
  db: D1Database,
  mcp: McpIdentity,
  action: 'add' | 'remove' | 'alerts_on' | 'digest_on',
  target: string,
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO watch_events (id, user_id, at, action, target, via, client_host)
       SELECT ?1, ?2, ?3, ?4, ?5, 'mcp', ?6 WHERE changes() > 0`,
    )
    .bind(crypto.randomUUID(), mcp.sub, new Date().toISOString(), action, target, clientHost(mcp.clientId));
}

/** SQL fragment: the user has removed fewer than the cap through MCP in the last 24 hours. `?1` is the user. */
export function removalCapSql(cutParam: string): string {
  return `(SELECT COUNT(*) FROM watch_events WHERE user_id = ?1 AND action = 'remove' AND at > ${cutParam}) < ${MCP_REMOVAL_CAP}`;
}

/** ISO time 24 hours before now. */
export const removalCut = (): string => new Date(Date.now() - DAY_MS).toISOString();

/** The 429 `removal_limit` answer, with Retry-After until the oldest removal in the window ages out. */
export async function removalLimitResponse(c: Context<AppEnv>, userId: string): Promise<Response> {
  const oldest = await c.env.DB_USERS.prepare(
    `SELECT MIN(at) AS at FROM watch_events WHERE user_id = ?1 AND action = 'remove' AND at > ?2`,
  )
    .bind(userId, removalCut())
    .first<{ at: string | null }>();
  const until = oldest?.at ? Date.parse(oldest.at) + DAY_MS : Date.now() + 3600_000;
  const seconds = Math.max(60, Math.ceil((until - Date.now()) / 1000));
  c.header('Retry-After', String(seconds));
  return c.json({ error: 'removal_limit' }, 429);
}
