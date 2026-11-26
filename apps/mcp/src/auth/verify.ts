import { MCP_SCOPES, type McpIdentity } from '@ti/core/mcp-user';
import { getSigningKey, JwksUnavailable } from './jwks';

export const CLOCK_LEEWAY_S = 5;
export const MAX_LIFETIME_S = 7 * 86_400;
export type AuthReason =
  | 'opaque'
  | 'bad_format'
  | 'bad_typ'
  | 'bad_alg'
  | 'bad_header'
  | 'unknown_kid'
  | 'bad_signature'
  | 'bad_iss'
  | 'bad_aud'
  | 'expired'
  | 'not_yet_valid'
  | 'bad_iat'
  | 'no_client'
  | 'bad_sub';
export type TokenResult =
  | { ok: true; identity: McpIdentity; expiresAt: number }
  | { ok: false; reason: AuthReason }
  | { ok: false; reason: 'unavailable' };

const PART = /^[A-Za-z0-9_-]+$/;
const dec = new TextDecoder();

function unb64u(s: string): Uint8Array | null {
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}
function jsonObject(part: string): Record<string, unknown> | null {
  const bytes = unb64u(part);
  if (!bytes) return null;
  try {
    const v = JSON.parse(dec.decode(bytes));
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
const fail = (reason: AuthReason): TokenResult => ({ ok: false, reason });

export async function verifyAccessToken(
  token: string,
  cfg: { issuer: string; resource: string },
  now = Math.floor(Date.now() / 1000),
): Promise<TokenResult> {
  if (token.startsWith('oat_')) return fail('opaque');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !PART.test(p))) return fail('bad_format');
  const [h, p, s] = parts as [string, string, string];
  const header = jsonObject(h);
  const payload = jsonObject(p);
  if (!header || !payload) return fail('bad_format');

  const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : '';
  if (typ !== 'at+jwt' && typ !== 'application/at+jwt') return fail('bad_typ');
  if (header.alg !== 'RS256') return fail('bad_alg');
  if (typeof header.kid !== 'string' || header.kid.length < 1 || header.kid.length > 128)
    return fail('bad_header');
  if ('crit' in header) return fail('bad_header');

  if (payload.iss !== cfg.issuer) return fail('bad_iss');
  const aud = payload.aud;
  const audOk =
    typeof aud === 'string'
      ? aud === cfg.resource
      : Array.isArray(aud) && aud.every((a) => typeof a === 'string') && aud.includes(cfg.resource);
  if (!audOk) return fail('bad_aud');
  const { exp, nbf, iat } = payload;
  if (typeof exp !== 'number' || !Number.isFinite(exp) || now > exp + CLOCK_LEEWAY_S) return fail('expired');
  if (nbf !== undefined && (typeof nbf !== 'number' || nbf > now + CLOCK_LEEWAY_S))
    return fail('not_yet_valid');
  if (
    typeof iat !== 'number' ||
    !Number.isFinite(iat) ||
    iat > now + CLOCK_LEEWAY_S ||
    exp - iat > MAX_LIFETIME_S
  )
    return fail('bad_iat');
  if (typeof payload.client_id !== 'string' || !/^[\x21-\x7e]{1,512}$/.test(payload.client_id))
    return fail('no_client');
  if (typeof payload.sub !== 'string' || !/^user_[A-Za-z0-9]{10,64}$/.test(payload.sub))
    return fail('bad_sub');

  let key: CryptoKey | null;
  try {
    key = await getSigningKey(cfg.issuer, header.kid);
  } catch (e) {
    if (e instanceof JwksUnavailable) return { ok: false, reason: 'unavailable' };
    throw e;
  }
  if (!key) return fail('unknown_kid');
  const sig = unb64u(s);
  if (!sig) return fail('bad_format');
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    sig,
    new TextEncoder().encode(`${h}.${p}`),
  );
  if (!valid) return fail('bad_signature');

  const scopes = [
    ...new Set(
      (typeof payload.scope === 'string' ? payload.scope.split(/\s+/) : []).filter(
        (x): x is (typeof MCP_SCOPES)[number] => (MCP_SCOPES as readonly string[]).includes(x),
      ),
    ),
  ].sort();
  return { ok: true, identity: { sub: payload.sub, scopes, clientId: payload.client_id }, expiresAt: exp };
}
