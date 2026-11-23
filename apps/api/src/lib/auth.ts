import { verifyWebhook } from '@clerk/backend/webhooks';
import { getAuth } from '@hono/clerk-auth';
import type { Context, MiddlewareHandler } from 'hono';
import type { AppEnv } from './env';

/**
 * Single-user accounts: we only ever read `userId` from Clerk, never `orgId`.
 */
export const requireUser: MiddlewareHandler<AppEnv> = async (c, next) => {
  const userId = getAuth(c)?.userId;
  if (!userId) return c.json({ error: 'sign_in_required' }, 401);
  c.set('userId', userId);
  await next();
};

/** Verifies a Svix-signed webhook (Clerk and Resend both use Svix). Throws when the signature is bad. */
export function verifySvix(c: Context<AppEnv>, signingSecret: string | undefined) {
  if (!signingSecret) throw new Error('webhook signing secret is not configured');
  return verifyWebhook(c.req.raw, { signingSecret });
}

const hex = (bytes: ArrayBuffer): string =>
  [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');

/** HMAC-SHA256 of `message`, as lowercase hex. */
export async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return hex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message)));
}

/** Constant-time check that `signature` is the HMAC of `message`. Fails closed without a secret. */
export async function verifyHmac(
  secret: string | undefined,
  message: string,
  signature: string | undefined | null,
): Promise<boolean> {
  if (!secret || !signature) return false;
  const expected = await hmacHex(secret, message);
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  return diff === 0;
}
