export class JwksUnavailable extends Error {}

const FRESH_MS = 10 * 60_000;
const REFRESH_GAP_MS = 30_000;
const MAX_BYTES = 65_536;
const MAX_KEYS = 20;
const RS256 = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const;

interface Cache {
  issuer: string;
  fetchedAt: number;
  keys: Map<string, CryptoKey>;
}
const state: { cache: Cache | null; inflight: { issuer: string; promise: Promise<Cache> } | null; lastRefreshAt: number } = {
  cache: null,
  inflight: null,
  lastRefreshAt: 0,
};

export function resetJwksCacheForTests(): void {
  state.cache = null;
  state.inflight = null;
  state.lastRefreshAt = 0;
}

function modulusBits(n: string): number {
  const b64 = n.replace(/-/g, '+').replace(/_/g, '/');
  try {
    const bytes = atob(b64);
    let i = 0;
    while (i < bytes.length && bytes.charCodeAt(i) === 0) i++;
    if (i >= bytes.length) return 0;
    return (bytes.length - i - 1) * 8 + (32 - Math.clz32(bytes.charCodeAt(i)));
  } catch {
    return 0;
  }
}

async function load(issuer: string, now: number): Promise<Cache> {
  let res: Response;
  try {
    res = await fetch(`${issuer}/.well-known/jwks.json`, {
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(3000),
    });
  } catch {
    throw new JwksUnavailable('fetch failed');
  }
  if (res.status !== 200) throw new JwksUnavailable('bad status');
  const buf = await res.arrayBuffer().catch(() => null);
  if (!buf || buf.byteLength > MAX_BYTES) throw new JwksUnavailable('bad size');
  let doc: { keys?: unknown };
  try {
    doc = JSON.parse(new TextDecoder().decode(buf));
  } catch {
    throw new JwksUnavailable('bad json');
  }
  if (!doc || !Array.isArray(doc.keys) || doc.keys.length > MAX_KEYS) throw new JwksUnavailable('bad keys');
  const keys = new Map<string, CryptoKey>();
  for (const k of doc.keys as Record<string, unknown>[]) {
    if (!k || k.kty !== 'RSA' || typeof k.kid !== 'string' || !k.kid) continue;
    if (k.use !== undefined && k.use !== 'sig') continue;
    if (k.alg !== undefined && k.alg !== 'RS256') continue;
    if (k.e !== 'AQAB' || typeof k.n !== 'string' || modulusBits(k.n) < 2048) continue;
    try {
      keys.set(
        k.kid,
        await crypto.subtle.importKey('jwk', { kty: 'RSA', n: k.n, e: 'AQAB', alg: 'RS256', ext: true }, RS256, false, ['verify']),
      );
    } catch {
      // skip a key that will not import
    }
  }
  if (keys.size === 0) throw new JwksUnavailable('no usable keys');
  return { issuer, fetchedAt: now, keys };
}

function refresh(issuer: string, now: number): Promise<Cache> {
  if (state.inflight && state.inflight.issuer === issuer) return state.inflight.promise;
  state.lastRefreshAt = now;
  const promise = load(issuer, now)
    .then((c) => {
      state.cache = c;
      return c;
    })
    .finally(() => {
      state.inflight = null;
    });
  state.inflight = { issuer, promise };
  return promise;
}

export async function getSigningKey(issuer: string, kid: string, now = Date.now()): Promise<CryptoKey | null> {
  const cache = state.cache;
  if (cache && cache.issuer === issuer && now - cache.fetchedAt < FRESH_MS) {
    const hit = cache.keys.get(kid);
    if (hit) return hit;
    if (now - state.lastRefreshAt < REFRESH_GAP_MS) return null;
    return (await refresh(issuer, now)).keys.get(kid) ?? null;
  }
  return (await refresh(issuer, now)).keys.get(kid) ?? null;
}
