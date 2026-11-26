import type { Env } from './env';

export const SERVER_INFO = { name: 'mti', title: 'MTI (Motiontic Threat Index)', version: '1.0.0' } as const;
/** The 2026-07-28 revision `server/discover` lists. SDK 2.4.0 does not export it. */
export const MODERN_PROTOCOL_VERSION = '2026-07-28';
export const MAX_RUN_MS = 30_000;
export const TOOLS_LIST_CACHE = { ttlMs: 3_600_000, cacheScope: 'public' } as const;

export function siteOrigin(env: Pick<Env, 'MCP_RESOURCE_URL'>): string {
  return new URL(env.MCP_RESOURCE_URL).origin;
}

function badUrl(raw: string | undefined): boolean {
  if (!raw) return true;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return true;
  }
  const secure = u.protocol === 'https:' || (u.protocol === 'http:' && u.hostname === 'localhost');
  return (
    !secure || u.search !== '' || u.hash !== '' || raw.endsWith('/') || u.username !== '' || u.password !== ''
  );
}

/** Names of the variables that are missing or malformed. Never their values. */
export function checkConfig(env: Env): string[] {
  const bad: string[] = [];
  if (badUrl(env.MCP_RESOURCE_URL)) bad.push('MCP_RESOURCE_URL');
  if (badUrl(env.CLERK_ISSUER)) bad.push('CLERK_ISSUER');
  if (!env.MCP_HMAC_SECRET) bad.push('MCP_HMAC_SECRET');
  return bad;
}
