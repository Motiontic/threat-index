import type { McpIdentity } from '@ti/core/mcp-user';
import { callApi } from '../api';
import type { Env } from '../env';

export const CALL_TIMEOUT_MS = 25_000;
export const CHECK_BODY_CAP = 4 * 1024 * 1024;
/** The deep-query job's own result cap (5 MiB) plus room for the rest of the API's answer. */
export const DEEP_BODY_CAP = 5 * 1024 * 1024 + 64 * 1024;
const SMALL_BODY_CAP = 4096;

export type ApiFn = (
  identity: McpIdentity,
  call: { method: string; path: string; body?: unknown; requestId: string },
) => Promise<Response>;

/** The default: ti-api over the service binding, each call with a fresh signed assertion and a 25 s limit. */
export const apiVia =
  (env: Env): ApiFn =>
  (identity, call) =>
    callApi(env, {
      method: call.method,
      path: call.path,
      body: call.body === undefined ? null : JSON.stringify(call.body),
      identity,
      requestId: call.requestId,
      signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
    });

export type Capped = { ok: true; value: unknown } | { ok: false; reason: 'too_large' | 'bad' };

/** Reads a JSON body up to `cap` bytes, and says why when it cannot: over the cap, or not JSON. */
export async function readJsonResult(res: Response, cap: number): Promise<Capped> {
  try {
    const reader = res.body?.getReader();
    if (!reader) return { ok: false, reason: 'bad' };
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > cap) {
        await reader.cancel().catch(() => {});
        return { ok: false, reason: 'too_large' };
      }
      chunks.push(value);
    }
    const buf = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      buf.set(c, off);
      off += c.length;
    }
    return { ok: true, value: JSON.parse(new TextDecoder().decode(buf)) };
  } catch {
    return { ok: false, reason: 'bad' };
  }
}

/** Reads a JSON body up to `cap` bytes. Null when it is over the cap or is not JSON. */
export async function readJsonCapped(res: Response, cap: number): Promise<unknown | null> {
  const r = await readJsonResult(res, cap);
  return r.ok ? r.value : null;
}

/** A small error body's `error` field, and the body is released either way. */
export async function errorName(res: Response): Promise<string | null> {
  const body = (await readJsonCapped(res, SMALL_BODY_CAP)) as { error?: unknown } | null;
  return typeof body?.error === 'string' ? body.error : null;
}

export function retryAfterSeconds(res: Response): number {
  const n = Number(res.headers.get('retry-after'));
  return Number.isInteger(n) && n > 0 && n <= 3600 ? n : 60;
}
