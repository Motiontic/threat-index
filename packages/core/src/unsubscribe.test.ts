import { describe, expect, it } from 'vitest';
import {
  MAX_UNSUBSCRIBE_TOKEN_CHARS,
  signUnsubscribeToken,
  type UnsubscribePayload,
  unsubscribeUrl,
  verifyUnsubscribeToken,
} from './unsubscribe';

const SECRET = 'test-unsubscribe-secret';
const base: UnsubscribePayload = { userId: 'user_1', scope: 'all', issuedAt: 1700000000 };
const b64u = (s: string) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function hmac(secret: string, msg: string) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
  return [...mac].map((b) => b.toString(16).padStart(2, '0')).join('');
}
/** A correctly signed token around an arbitrary JSON body. */
async function raw(json: unknown) {
  const body = b64u(JSON.stringify(json));
  return `${body}.${await hmac(SECRET, body)}`;
}
const flip = (s: string, i: number) => s.slice(0, i) + (s[i] === 'a' ? 'b' : 'a') + s.slice(i + 1);

describe('unsubscribe tokens', () => {
  it('matches the fixed vector (the notify worker copies this)', async () => {
    const token = await signUnsubscribeToken(SECRET, base);
    expect(token).toBe(
      'eyJ2IjoxLCJ1IjoidXNlcl8xIiwicyI6ImFsbCIsInQiOjE3MDAwMDAwMDB9.9c530741a6970d46e990807574f3b5402ab532b60b274e7335a8b27509e86605',
    );
  });

  it.each<UnsubscribePayload>([
    base,
    { userId: 'user_1', scope: 'digest', issuedAt: 0 },
    { userId: 'user_2', scope: 'watch', item: 'CVE-2025-0001', issuedAt: 1700000001 },
    { userId: 'user_3', scope: 'search', item: 'ss_9', issuedAt: 1700000002 },
  ])('round trips scope $scope', async (p) => {
    expect(await verifyUnsubscribeToken(SECRET, await signUnsubscribeToken(SECRET, p))).toEqual(p);
  });

  it('only emits URL-safe characters', async () => {
    const t = await signUnsubscribeToken(SECRET, { ...base, scope: 'watch', item: 'a/b?c=d é', issuedAt: 5 });
    expect(t).toMatch(/^[A-Za-z0-9_.-]+$/);
    expect((await verifyUnsubscribeToken(SECRET, t))?.item).toBe('a/b?c=d é');
  });

  it('verifies to null for anything wrong', async () => {
    const good = await signUnsubscribeToken(SECRET, base);
    const other = await signUnsubscribeToken('another-secret', base);
    const dot = good.lastIndexOf('.');
    const cases: Array<[string, string | undefined | null]> = [
      ['other secret', other],
      ['flipped payload byte', flip(good, 3)],
      ['flipped hmac char', flip(good, dot + 5)],
      ['truncated', good.slice(0, good.length - 10)],
      ['over-long', `${'a'.repeat(MAX_UNSUBSCRIBE_TOKEN_CHARS)}.${'0'.repeat(64)}`],
      ['no dot', good.replace('.', '')],
      ['empty', ''],
      ['undefined', undefined],
      ['null', null],
      ['v 2', await raw({ v: 2, u: 'user_1', s: 'all', t: 1700000000 })],
      ['item on all', await raw({ v: 1, u: 'user_1', s: 'all', i: 'x', t: 1700000000 })],
      ['watch without item', await raw({ v: 1, u: 'user_1', s: 'watch', t: 1700000000 })],
      ['unknown scope', await raw({ v: 1, u: 'user_1', s: 'nuke', t: 1700000000 })],
      ['empty user', await raw({ v: 1, u: '', s: 'all', t: 1700000000 })],
      ['fractional time', await raw({ v: 1, u: 'user_1', s: 'all', t: 1.5 })],
      ['negative time', await raw({ v: 1, u: 'user_1', s: 'all', t: -1 })],
      ['non-string user', await raw({ v: 1, u: 7, s: 'all', t: 1 })],
      ['bad json', `${b64u('not json')}.${await hmac(SECRET, b64u('not json'))}`],
      ['bad base64url', `a*b.${await hmac(SECRET, 'a*b')}`],
    ];
    for (const [name, token] of cases) {
      expect(await verifyUnsubscribeToken(SECRET, token), name).toBeNull();
    }
    expect(await verifyUnsubscribeToken('', good)).toBeNull();
    expect(await verifyUnsubscribeToken(undefined, good)).toBeNull();
  });

  it('sign throws on bad input', async () => {
    const bad: Array<[string, string, UnsubscribePayload]> = [
      ['empty secret', '', base],
      ['empty userId', SECRET, { ...base, userId: '' }],
      ['long userId', SECRET, { ...base, userId: 'u'.repeat(257) }],
      ['long item', SECRET, { ...base, scope: 'watch', item: 'i'.repeat(257) }],
      ['unknown scope', SECRET, { ...base, scope: 'nope' as never }],
      ['watch without item', SECRET, { ...base, scope: 'watch' }],
      ['search without item', SECRET, { ...base, scope: 'search' }],
      ['item on all', SECRET, { ...base, item: 'x' }],
      ['item on digest', SECRET, { ...base, scope: 'digest', item: 'x' }],
      ['fractional issuedAt', SECRET, { ...base, issuedAt: 1.5 }],
      ['negative issuedAt', SECRET, { ...base, issuedAt: -1 }],
    ];
    for (const [name, secret, p] of bad) {
      await expect(signUnsubscribeToken(secret, p), name).rejects.toThrow();
    }
  });

  it('builds the URL without a doubled slash', () => {
    expect(unsubscribeUrl('https://api.example.com/', 'abc.def')).toBe('https://api.example.com/unsubscribe?t=abc.def');
    expect(unsubscribeUrl('https://api.example.com', 'abc.def')).toBe('https://api.example.com/unsubscribe?t=abc.def');
  });
});
