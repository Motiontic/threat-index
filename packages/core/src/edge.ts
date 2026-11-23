// The signed client IP ti-web passes to ti-api over the service binding (a binding call has no
// CF-Connecting-IP). The API trusts it only with a valid HMAC from the shared EDGE_HMAC_SECRET.
import { constantTimeEqual, hmac } from './sign';

export const CLIENT_IP_HEADER = 'x-ti-client-ip';
export const CLIENT_TS_HEADER = 'x-ti-client-ts';
export const CLIENT_SIG_HEADER = 'x-ti-client-sig';
export const CLIENT_SKEW_SECONDS = 60;

/** hex(HMAC-SHA256(secret, `client-ip\n${ip}\n${ts}\n${requestId}`)). */
export function signClientIp(secret: string, ip: string, ts: number, requestId: string): Promise<string> {
  return hmac(secret, `client-ip\n${ip}\n${ts}\n${requestId}`);
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6 = /^[0-9a-fA-F:.]{2,45}$/;

function isIp(ip: string): boolean {
  const m = IPV4.exec(ip);
  if (m) return m.slice(1).every((p) => Number(p) <= 255);
  return IPV6.test(ip) && ip.includes(':') && (ip.match(/::/g) ?? []).length <= 1;
}

/** The client IP the web Worker vouched for, or null. Fails closed on anything off. */
export async function verifiedClientIp(
  secret: string | undefined,
  h: Headers,
  now: Date = new Date(),
): Promise<string | null> {
  if (!secret) return null;
  const ip = h.get(CLIENT_IP_HEADER);
  const tsRaw = h.get(CLIENT_TS_HEADER);
  const sig = h.get(CLIENT_SIG_HEADER);
  const requestId = h.get('x-request-id');
  if (!ip || !tsRaw || !sig || !requestId) return null;
  if (!/^\d{1,15}$/.test(tsRaw)) return null;
  const ts = Number(tsRaw);
  if (Math.abs(now.getTime() / 1000 - ts) > CLIENT_SKEW_SECONDS) return null;
  if (!isIp(ip)) return null;
  const expected = await signClientIp(secret, ip, ts, requestId);
  return constantTimeEqual(expected, sig) ? ip : null;
}

/** The rate-limit key part: IPv4 as is; IPv6 cut to its first four hextets (a /64). */
export function ipKey(ip: string): string {
  if (!ip.includes(':')) return ip;
  const [head = '', tail = ''] = ip.toLowerCase().split('::');
  const first = head === '' ? [] : head.split(':');
  const last = ip.includes('::') && tail !== '' ? tail.split(':') : [];
  const missing = ip.includes('::') ? 8 - first.length - last.length : 0;
  const full = ip.includes('::') ? [...first, ...Array(Math.max(0, missing)).fill('0'), ...last] : first;
  return full
    .slice(0, 4)
    .map((x) => x.replace(/^0+(?=.)/, ''))
    .join(':');
}
