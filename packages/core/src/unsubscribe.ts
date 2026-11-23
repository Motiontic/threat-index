/**
 * Signed unsubscribe tokens, shared by the API route (verifies) and the notify worker (signs).
 * Format: `<payload>.<hmac>`; payload = base64url (no padding) of the UTF-8 JSON
 * `{"v":1,"u":userId,"s":scope,"i":item?,"t":issuedAt}`; hmac = lowercase hex HMAC-SHA256 of the payload string.
 * Web Crypto only, so it runs in Workers and Node.
 */
export const UNSUBSCRIBE_PATH = '/unsubscribe';
export const MAX_UNSUBSCRIBE_TOKEN_CHARS = 1024;
const MAX_FIELD_CHARS = 256;

export type UnsubscribeScope = 'all' | 'digest' | 'watch' | 'search';
/** `item` is the entry key for 'watch' and the saved-search id for 'search'; absent otherwise. */
export interface UnsubscribePayload {
  userId: string;
  scope: UnsubscribeScope;
  item?: string;
  issuedAt: number;
}

const SCOPES: readonly string[] = ['all', 'digest', 'watch', 'search'];
const encoder = new TextEncoder();

/** Returns a reason when the payload is not one we sign or accept, else null. */
function problem(p: UnsubscribePayload): string | null {
  if (typeof p.userId !== 'string' || p.userId === '' || p.userId.length > MAX_FIELD_CHARS)
    return 'bad userId';
  if (!SCOPES.includes(p.scope)) return 'unknown scope';
  const needsItem = p.scope === 'watch' || p.scope === 'search';
  if (needsItem) {
    if (typeof p.item !== 'string' || p.item === '') return 'missing item';
    if (p.item.length > MAX_FIELD_CHARS) return 'item too long';
  } else if (p.item !== undefined) return 'unexpected item';
  if (!Number.isInteger(p.issuedAt) || p.issuedAt < 0) return 'bad issuedAt';
  return null;
}

function toBase64Url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  try {
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(message)));
  return [...mac].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function signUnsubscribeToken(secret: string, payload: UnsubscribePayload): Promise<string> {
  if (!secret) throw new Error('unsubscribe secret is empty');
  const why = problem(payload);
  if (why) throw new Error(`invalid unsubscribe payload: ${why}`);
  const json: Record<string, unknown> = { v: 1, u: payload.userId, s: payload.scope };
  if (payload.item !== undefined) json.i = payload.item;
  json.t = payload.issuedAt;
  const body = toBase64Url(encoder.encode(JSON.stringify(json)));
  return `${body}.${await hmacHex(secret, body)}`;
}

export async function verifyUnsubscribeToken(
  secret: string | undefined,
  token: string | undefined | null,
): Promise<UnsubscribePayload | null> {
  if (!secret || !token || token.length > MAX_UNSUBSCRIBE_TOKEN_CHARS) return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const body = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  try {
    const expected = await hmacHex(secret, body);
    if (expected.length !== mac.length) return null;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ mac.charCodeAt(i);
    if (diff !== 0) return null;

    const bytes = fromBase64Url(body);
    if (!bytes) return null;
    const j = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Record<string, unknown>;
    if (typeof j !== 'object' || j === null || j.v !== 1) return null;
    const payload = {
      userId: j.u,
      scope: j.s,
      ...(j.i === undefined ? {} : { item: j.i }),
      issuedAt: j.t,
    } as UnsubscribePayload;
    return problem(payload) ? null : payload;
  } catch {
    return null;
  }
}

/** `${apiBase without trailing slash}/unsubscribe?t=${token}` — the URL for the link and List-Unsubscribe. */
export function unsubscribeUrl(apiBase: string, token: string): string {
  return `${apiBase.replace(/\/+$/, '')}${UNSUBSCRIBE_PATH}?t=${token}`;
}
