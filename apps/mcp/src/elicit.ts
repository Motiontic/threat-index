import { acceptedContent, inputRequired } from '@modelcontextprotocol/server';
import { canonical } from './cursor';
import type { Env } from './env';

/**
 * The yes/no question asked when a user adds a watch while their email alerts are off, and the sealed
 * `requestState` that carries the first call's outcome to the retry.
 *
 * The state is AES-GCM under `MCP_STATE_KEY` (not the HMAC secret) and binds the user, the tool, the
 * arguments, an expiry and a random nonce. It comes back from the client, so it is opened inside the tool:
 * a bad one gets the tool error `invalid_argument` on `requestState`, not the SDK's -32602.
 */
export const STATE_TTL_S = 600;
export const FORM_MESSAGE = 'Email alerts are off for your MTI account. Turn on an alert digest?';
export const FORM_KEY = 'alerts';
export const FREQUENCIES = ['daily', 'weekly'] as const;
export type Frequency = (typeof FREQUENCIES)[number];

/** Fixed text only: no URL, no advisory or package text, and no field that could carry an address. */
export const FORM_SCHEMA = {
  type: 'object',
  properties: {
    enable: { type: 'boolean', title: 'Turn on email alerts' },
    frequency: { type: 'string', title: 'How often', enum: [...FREQUENCIES], default: 'daily' },
  },
  required: ['enable'],
} as const;

export interface WatchState {
  created: boolean;
  /** The watch target, as the first call stored it. */
  target: { kind: 'package'; ecosystem: string; name: string } | { kind: 'entry'; entryId: string };
}
interface Sealed extends WatchState {
  sub: string;
  tool: string;
  h: string;
  exp: number;
  n: string;
}
export interface Binding {
  sub: string;
  tool: string;
  args: Record<string, unknown>;
}

const enc = new TextEncoder();
const b64u = (b: Uint8Array): string => {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const unb64u = (s: string): Uint8Array | null => {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return null;
  try {
    return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
};

async function aesKey(secret: string, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const raw = await crypto.subtle.digest('SHA-256', enc.encode(`mcp-state/v1\n${secret}`));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [usage]);
}
async function hashArgs(args: Record<string, unknown>): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(canonical(args)));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
const AAD = enc.encode('mcp-requestState/v1');

/** The key to seal with: the current one. Null when it is not set (then nothing is elicited). */
export const sealingKey = (env: Pick<Env, 'MCP_STATE_KEY'>): string | null => env.MCP_STATE_KEY || null;

export async function sealState(
  key: string,
  bind: Binding,
  state: WatchState,
  nowS = Math.floor(Date.now() / 1000),
): Promise<string> {
  const payload: Sealed = {
    ...state,
    sub: bind.sub,
    tool: bind.tool,
    h: await hashArgs(bind.args),
    exp: nowS + STATE_TTL_S,
    n: b64u(crypto.getRandomValues(new Uint8Array(12))),
  };
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: AAD },
      await aesKey(key, 'encrypt'),
      enc.encode(JSON.stringify(payload)),
    ),
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return b64u(out);
}

/** The state when it opens under a current key, has not expired, and was sealed for this user, tool and these arguments. */
export async function openState(
  keys: (string | undefined)[],
  token: string,
  bind: Binding,
  nowS = Math.floor(Date.now() / 1000),
): Promise<WatchState | null> {
  if (token.length > 2048) return null;
  const bytes = unb64u(token);
  if (!bytes || bytes.length < 12 + 16) return null;
  const iv = bytes.slice(0, 12);
  const ct = bytes.slice(12);
  for (const k of keys) {
    if (!k) continue;
    let plain: ArrayBuffer;
    try {
      plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: AAD },
        await aesKey(k, 'decrypt'),
        ct,
      );
    } catch {
      continue;
    }
    let p: Sealed;
    try {
      p = JSON.parse(new TextDecoder().decode(plain)) as Sealed;
    } catch {
      return null;
    }
    if (typeof p.exp !== 'number' || p.exp < nowS) return null;
    if (p.sub !== bind.sub || p.tool !== bind.tool || p.h !== (await hashArgs(bind.args))) return null;
    if (typeof p.created !== 'boolean' || !p.target || typeof p.target !== 'object') return null;
    return { created: p.created, target: p.target };
  }
  return null;
}

/** The `input_required` result: the fixed form, and the sealed state for the retry. */
export function askAlerts(requestState: string) {
  return inputRequired({
    inputRequests: {
      [FORM_KEY]: inputRequired.elicit({ message: FORM_MESSAGE, requestedSchema: FORM_SCHEMA as never }),
    },
    requestState,
  });
}

export type Answer =
  | { kind: 'enable'; frequency: Frequency }
  | { kind: 'off' } // declined, cancelled, no answer or `enable: false`
  | { kind: 'invalid' };

/** Reads the client's answer. Validated against the form: `enable` is a boolean, `frequency` daily or weekly. */
export function readAnswer(inputResponses: Record<string, unknown> | undefined): Answer {
  const entry = inputResponses?.[FORM_KEY];
  if (entry === undefined) return { kind: 'off' };
  const c = acceptedContent(inputResponses, FORM_KEY) as Record<string, unknown> | undefined;
  if (c === undefined) return { kind: 'off' }; // declined or cancelled
  if (!c || typeof c !== 'object' || typeof c.enable !== 'boolean') return { kind: 'invalid' };
  const f = c.frequency;
  if (f !== undefined && !(typeof f === 'string' && (FREQUENCIES as readonly string[]).includes(f)))
    return { kind: 'invalid' };
  return c.enable ? { kind: 'enable', frequency: (f as Frequency | undefined) ?? 'daily' } : { kind: 'off' };
}
