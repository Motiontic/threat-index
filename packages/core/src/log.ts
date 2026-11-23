// Structured, redacted logging shared by ti-api and ti-web. One JSON line per event.
export const REQUEST_ID_HEADER = 'x-request-id';

const ID = /^[A-Za-z0-9-]{8,64}$/;

/** Keeps a well-formed incoming id, otherwise makes a fresh one. */
export function requestIdFrom(raw: string | null): string {
  return raw !== null && ID.test(raw) ? raw : crypto.randomUUID();
}

const SECRET_KEY = /email|token|secret|password|authorization|cookie|signature|ip$/i;
const EMAIL = /[^\s@]+@[^\s@]+\.[^\s@]+/;
const MAX_STRING = 200;

/** Primitives only; drops sensitive keys, redacts strings holding an email, cuts strings to 200 characters. */
export function safeFields(f: Record<string, unknown>): Record<string, string | number | boolean | null> {
  const out: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(f)) {
    if (SECRET_KEY.test(key)) continue;
    if (value === null || typeof value === 'number' || typeof value === 'boolean') out[key] = value;
    else if (typeof value === 'string')
      out[key] = EMAIL.test(value) ? '[redacted]' : value.slice(0, MAX_STRING);
  }
  return out;
}

export function logEvent(
  level: 'info' | 'warn' | 'error',
  event: string,
  f: Record<string, unknown> = {},
): void {
  const line = JSON.stringify({ level, event, ...safeFields(f) });
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}
