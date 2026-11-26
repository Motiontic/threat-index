import { ipKey, verifiedClientIp } from '@ti/core/edge';
import { logEvent } from '@ti/core/log';
import type { Context, MiddlewareHandler } from 'hono';
import { currentUserId } from './auth';
import type { AppEnv, RateLimiter } from './env';

export const RETRY_AFTER_SECONDS = 60;
let warnedNoClient = false;

/** The IP the web Worker vouched for, else CF-Connecting-IP, else null. */
export async function clientIp(c: Context<AppEnv>): Promise<string | null> {
  const signed = await verifiedClientIp(c.env.EDGE_HMAC_SECRET, c.req.raw.headers);
  return signed ?? c.req.header('cf-connecting-ip') ?? null;
}

/** True when `key` is allowed. A missing binding or a throwing `limit()` fails open. */
export async function allow(binding: RateLimiter | undefined, key: string): Promise<boolean> {
  if (!binding) {
    logEvent('warn', 'rate_limit_unavailable', { reason: 'no_binding' });
    return true;
  }
  try {
    return (await binding.limit({ key })).success;
  } catch {
    logEvent('warn', 'rate_limit_unavailable', { reason: 'limit_threw' });
    return true;
  }
}

export function limited(c: Context<AppEnv>): Response {
  c.set('limited', true);
  return c.json(
    { error: 'rate_limited', retryAfter: RETRY_AFTER_SECONDS, requestId: c.get('requestId') },
    429,
    {
      'Retry-After': String(RETRY_AFTER_SECONDS),
      'Cache-Control': 'no-store',
    },
  );
}

/** Per-user limit when signed in (a session or a verified MCP identity), else per-IP. Runs before any cache, so cache hits count. */
export const rateLimit: MiddlewareHandler<AppEnv> = async (c, next) => {
  const userId = currentUserId(c);
  if (userId) {
    if (!(await allow(c.env.RL_USER, `u:${userId}`))) return limited(c);
    return next();
  }
  const ip = await clientIp(c);
  if (!ip) {
    if (!warnedNoClient) {
      warnedNoClient = true;
      logEvent('warn', 'rate_limit_no_client');
    }
    return next();
  }
  if (!(await allow(c.env.RL_PUBLIC, `ip:${ipKey(ip)}`))) return limited(c);
  return next();
};
