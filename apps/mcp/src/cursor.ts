import { constantTimeEqual, hmac } from '@ti/core/sign';
import type { ToolName } from './tools';

export type CursorState = { c: string } | { p: number; k: number } | { o: number } | { t: string; o: number };
export const CURSOR_TTL_S = 3600;
export const MAX_CURSOR_CHARS = 512;

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64u(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64u(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object')
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`)
      .join(',')}}`;
  return JSON.stringify(v) ?? 'null';
}

/** Hash of the arguments without `cursor`, and of the caller, so a cursor only opens for who it was made for. */
async function argsHash(args: Record<string, unknown>, sub: string): Promise<string> {
  const { cursor: _cursor, ...rest } = args;
  const d = await crypto.subtle.digest('SHA-256', enc.encode(canonical({ args: rest, sub })));
  return [...new Uint8Array(d)]
    .slice(0, 8)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function macKey(secret: string, payload: string): Promise<string> {
  return hmac(await hmac(secret, 'mcp-cursor/v1'), payload);
}

export async function sealCursor(
  secret: string,
  tool: ToolName,
  args: Record<string, unknown>,
  state: CursorState,
  sub: string,
  now = Math.floor(Date.now() / 1000),
): Promise<string> {
  const payload = b64u(
    enc.encode(
      JSON.stringify({ v: 1, t: tool, h: await argsHash(args, sub), x: now + CURSOR_TTL_S, s: state }),
    ),
  );
  return `${payload}.${b64u(enc.encode(await macKey(secret, payload)))}`;
}

const int = (n: unknown, lo: number, hi: number): n is number =>
  typeof n === 'number' && Number.isInteger(n) && n >= lo && n <= hi;

function validState(s: unknown): s is CursorState {
  if (!s || typeof s !== 'object') return false;
  const o = s as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(',');
  if (keys === 'c') return typeof o.c === 'string' && /^[A-Za-z0-9_-]{1,200}$/.test(o.c);
  if (keys === 'k,p') return int(o.p, 1, 40) && int(o.k, 0, 24);
  if (keys === 'o') return int(o.o, 0, 1000);
  if (keys === 'o,t')
    return int(o.o, 0, 20_000) && typeof o.t === 'string' && /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(o.t);
  return false;
}

/** Null for anything wrong: length, shape, MAC, tool, arguments, expiry, or a state value out of range. */
export async function openCursor(
  secrets: (string | undefined)[],
  tool: ToolName,
  args: Record<string, unknown>,
  cursor: string,
  sub: string,
  now = Math.floor(Date.now() / 1000),
): Promise<CursorState | null> {
  if (typeof cursor !== 'string' || cursor.length > MAX_CURSOR_CHARS) return null;
  const parts = cursor.split('.');
  if (parts.length !== 2) return null;
  const [payload, mac] = parts as [string, string];
  const macBytes = unb64u(mac);
  if (!unb64u(payload) || !macBytes) return null;
  const macText = dec.decode(macBytes);
  let good = false;
  for (const secret of secrets) {
    if (!secret) continue;
    if (constantTimeEqual(await macKey(secret, payload), macText)) good = true;
  }
  if (!good) return null;
  let body: { v?: unknown; t?: unknown; h?: unknown; x?: unknown; s?: unknown };
  try {
    body = JSON.parse(dec.decode(unb64u(payload) as Uint8Array));
  } catch {
    return null;
  }
  if (!body || typeof body !== 'object') return null;
  if (body.v !== 1 || body.t !== tool || body.h !== (await argsHash(args, sub))) return null;
  if (typeof body.x !== 'number' || body.x < now) return null;
  return validState(body.s) ? body.s : null;
}
