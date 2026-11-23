/**
 * Request signing for every internal call: the collector asking ti-api to start a job, and a sandbox
 * calling `upload-urls` and `complete`. Web Crypto only, so it runs in Workers, Node 22 and E2B.
 */
export const SIGNATURE_HEADER = 'x-ti-signature';
export const TIMESTAMP_HEADER = 'x-ti-timestamp';
export const MAX_SKEW_SECONDS = 300;

const enc = new TextEncoder();

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hmac(key: string, message: string): Promise<string> {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  return toHex(await crypto.subtle.sign('HMAC', k, enc.encode(message)));
}

async function sha256Hex(text: string): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}

/** hex(HMAC-SHA256(key, `${METHOD}\n${path}\n${timestamp}\n${hex(SHA-256(body))}`)). `path` has no query. */
export async function signRequest(
  key: string,
  method: string,
  path: string,
  timestamp: number,
  body: string,
): Promise<string> {
  return hmac(key, `${method.toUpperCase()}\n${path}\n${timestamp}\n${await sha256Hex(body)}`);
}

function constantTimeEqual(a: string, b: string): boolean {
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

/** Constant-time check, rejects a timestamp more than MAX_SKEW_SECONDS from `now`. Fails closed on a missing key. */
export async function verifyRequest(
  key: string | undefined,
  req: { method: string; path: string; timestamp: string | null; signature: string | null; body: string },
  now: Date = new Date(),
): Promise<boolean> {
  if (!key || !req.signature || !req.timestamp) return false;
  if (!/^\d{1,15}$/.test(req.timestamp)) return false;
  const ts = Number(req.timestamp);
  if (Math.abs(now.getTime() / 1000 - ts) > MAX_SKEW_SECONDS) return false;
  const expected = await signRequest(key, req.method, req.path, ts, req.body);
  return constantTimeEqual(expected, req.signature);
}

/**
 * The per-job key a sandbox gets: hex(HMAC-SHA256(secret, `job:${jobId}`)). The sandbox never sees `secret`.
 * Throws on an empty secret.
 */
export async function deriveJobKey(secret: string, jobId: string): Promise<string> {
  if (!secret) throw new Error('deriveJobKey: empty secret');
  return hmac(secret, `job:${jobId}`);
}
