import { describe, expect, it } from 'vitest';
import { emailIdempotencyKey } from './email';
import {
  signUnsubscribeToken,
  UNSUBSCRIBE_PATH,
  unsubscribeUrl,
  verifyUnsubscribeToken,
} from './unsubscribe';

describe('emailIdempotencyKey', () => {
  it('is stable, order-independent and hides the user', async () => {
    const a = await emailIdempotencyKey('user_1', 'instant', ['c2', 'c1']);
    expect(a).toMatch(/^ti-instant-[0-9a-f]{40}$/);
    expect(await emailIdempotencyKey('user_1', 'instant', ['c1', 'c2'])).toBe(a);
    expect(a).not.toContain('user_1');
  });
  it('changes with user, kind and ids', async () => {
    const base = await emailIdempotencyKey('u1', 'daily', ['a']);
    expect(await emailIdempotencyKey('u2', 'daily', ['a'])).not.toBe(base);
    expect(await emailIdempotencyKey('u1', 'weekly', ['a'])).not.toBe(base);
    expect(await emailIdempotencyKey('u1', 'daily', ['a', 'b'])).not.toBe(base);
    expect(await emailIdempotencyKey('u1', 'daily', ['b'])).not.toBe(base);
  });
});

/** HMAC-SHA256 as lowercase hex, computed here and not with the code under test. */
async function hmacHex(secret: string, msg: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
  return Array.from(mac, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('unsubscribe token contract used by notify', () => {
  it('a signed token matches an independently computed HMAC and verifies', async () => {
    const secret = 'shh';
    const token = await signUnsubscribeToken(secret, { userId: 'u1', scope: 'digest', issuedAt: 5 });
    const [payload, sig] = token.split('.');
    expect(sig).toBe(await hmacHex(secret, payload as string));
    expect(await verifyUnsubscribeToken(secret, token)).toMatchObject({ userId: 'u1', scope: 'digest' });
    expect(unsubscribeUrl('https://api.example/', token)).toBe(
      `https://api.example${UNSUBSCRIBE_PATH}?t=${token}`,
    );
  });
});
