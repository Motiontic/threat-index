import { ipKey } from '@ti/core/edge';
import { logEvent } from '@ti/core/log';
import type { Env } from './env';

export const DEFAULT_ANON_EXEMPT_CIDRS = ['160.79.104.0/21', '153.61.208.0/20'] as const;

export interface Cidr {
  family: 4 | 6;
  bits: bigint;
  prefix: number;
}

function parseIp(ip: string): { family: 4 | 6; bits: bigint } | null {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.some((n) => n > 255)) return null;
    return { family: 4, bits: parts.reduce((a, n) => (a << 8n) | BigInt(n), 0n) };
  }
  if (!ip.includes(':') || !/^[0-9a-fA-F:.]+$/.test(ip)) return null;
  let head = ip;
  let tail4: bigint | null = null;
  const lastColon = ip.lastIndexOf(':');
  if (ip.slice(lastColon + 1).includes('.')) {
    const v4 = parseIp(ip.slice(lastColon + 1));
    if (!v4 || v4.family !== 4) return null;
    tail4 = v4.bits;
    head = `${ip.slice(0, lastColon + 1)}0:0`;
  }
  const dbl = head.split('::');
  if (dbl.length > 2) return null;
  const grp = (s: string) => (s === '' ? [] : s.split(':'));
  const a = grp(dbl[0] as string);
  const b = dbl.length === 2 ? grp(dbl[1] as string) : [];
  const missing = 8 - a.length - b.length;
  if ((dbl.length === 1 && missing !== 0) || missing < (dbl.length === 2 ? 1 : 0)) return null;
  const groups = [...a, ...Array(dbl.length === 2 ? missing : 0).fill('0'), ...b];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  let bits = groups.reduce((acc, g) => (acc << 16n) | BigInt(Number.parseInt(g, 16)), 0n);
  if (tail4 !== null) bits = (bits & ~0xffffffffn) | tail4;
  return { family: 6, bits };
}

export function parseCidrs(raw: string | undefined): Cidr[] {
  const out: Cidr[] = [];
  for (const item of (raw ?? '').split(',')) {
    const [ip, len, ...rest] = item.trim().split('/');
    if (!ip || len === undefined || rest.length || !/^\d{1,3}$/.test(len)) continue;
    const parsed = parseIp(ip);
    const prefix = Number(len);
    if (!parsed || prefix > (parsed.family === 4 ? 32 : 128)) continue;
    out.push({ family: parsed.family, bits: parsed.bits, prefix });
  }
  return out;
}

export function ipInCidrs(ip: string, cidrs: Cidr[]): boolean {
  const parsed = parseIp(ip);
  if (!parsed) return false;
  const width = parsed.family === 4 ? 32n : 128n;
  return cidrs.some((c) => {
    if (c.family !== parsed.family) return false;
    const shift = width - BigInt(c.prefix);
    return parsed.bits >> shift === c.bits >> shift;
  });
}

/** cf-connecting-ip, only when it is a valid IPv4 or IPv6 literal. */
export function clientIp(request: Request): string | null {
  const raw = request.headers.get('cf-connecting-ip')?.trim();
  return raw && parseIp(raw) ? raw : null;
}

/** True when the request is over the no-token limit. A limiter error lets it through. */
export async function limitAnon(env: Env, request: Request): Promise<boolean> {
  const ip = clientIp(request);
  const cidrs =
    env.MCP_ANON_EXEMPT_CIDRS !== undefined
      ? parseCidrs(env.MCP_ANON_EXEMPT_CIDRS)
      : parseCidrs(DEFAULT_ANON_EXEMPT_CIDRS.join(','));
  if (ip && ipInCidrs(ip, cidrs)) return false;
  if (!env.RL_MCP_ANON) return false;
  try {
    const { success } = await env.RL_MCP_ANON.limit({ key: `ip:${ip ? ipKey(ip) : 'unknown'}` });
    return !success;
  } catch {
    logEvent('warn', 'mcp_limiter_error', { limiter: 'anon' });
    return false;
  }
}
