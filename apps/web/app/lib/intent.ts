// "Return to intent": a locked action taken signed out is remembered in sessionStorage, and run once after
// sign-in. Storage can be missing or throw; every failure is swallowed and means "no intent".

export type Intent =
  | { action: 'watch'; target: string }
  | { action: 'save-search'; target: string }
  | { action: 'tab'; target: string };
export type StoredIntent = Intent & { at: number };

export const INTENT_KEY = 'ti:intent';
export const MAX_INTENT_CHARS = 600;
export const MAX_INTENT_AGE_MS = 30 * 60 * 1000;

export function saveIntent(intent: Intent, now: number = Date.now()): void {
  try {
    const text = JSON.stringify({ ...intent, at: now });
    if (text.length > MAX_INTENT_CHARS) return;
    sessionStorage.setItem(INTENT_KEY, text);
  } catch {
    // storage unavailable: the visitor just repeats the action after signing in
  }
}

/** Reads and clears the intent. Clears first, then validates shape, length and age; anything else → null. */
export function takeIntent(now: number = Date.now()): StoredIntent | null {
  let raw: string | null;
  try {
    raw = sessionStorage.getItem(INTENT_KEY);
    sessionStorage.removeItem(INTENT_KEY);
  } catch {
    return null;
  }
  if (raw === null || raw.length > MAX_INTENT_CHARS) return null;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (typeof o.at !== 'number' || !Number.isFinite(o.at)) return null;
  if (o.at > now + 60_000 || now - o.at > MAX_INTENT_AGE_MS) return null;
  if (typeof o.target !== 'string' || o.target.length === 0) return null;
  if (o.action !== 'watch' && o.action !== 'save-search' && o.action !== 'tab') return null;
  if (o.action === 'tab' && !/^[A-Za-z0-9._:-]+#[a-z]+$/.test(o.target)) return null;
  if (o.action === 'watch' && !/^[A-Za-z0-9._:-]+$/.test(o.target)) return null;
  return { action: o.action, target: o.target, at: o.at };
}
