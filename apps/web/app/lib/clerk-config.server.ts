// Reads the Clerk keys from the Worker env and checks them. Anything off about them turns Clerk OFF: every
// page then renders signed out and sign-in says it is unavailable (fail closed; public pages keep working).

export interface ClerkConfig {
  /** The public key, safe to send to the browser. */
  publishableKey: string;
  /** The host Clerk serves its scripts and API from, decoded from the key. */
  frontendApi: string;
}

const KEY = /^pk_(test|live)_([A-Za-z0-9+/_-]+={0,2})$/;
const HOST = /^[a-z0-9.-]+$/;

/** `pk_(test|live)_` + base64 of `<host>$`. The host must be a Clerk dev domain (test) or `clerk.*` (live). */
export function decodePublishableKey(key: string): { frontendApi: string; live: boolean } | null {
  const m = KEY.exec(key);
  if (!m) return null;
  let text: string;
  try {
    text = atob((m[2] as string).replace(/-/g, '+').replace(/_/g, '/'));
  } catch {
    return null;
  }
  if (!text.endsWith('$')) return null;
  const host = text.slice(0, -1);
  if (!HOST.test(host) || host.length > 253) return null;
  const live = m[1] === 'live';
  const ok = live ? host.startsWith('clerk.') : host.endsWith('.clerk.accounts.dev');
  return ok ? { frontendApi: host, live } : null;
}

export function clerkConfig(env: {
  CLERK_PUBLISHABLE_KEY?: string;
  CLERK_SECRET_KEY?: string;
}): ClerkConfig | null {
  const secret = env.CLERK_SECRET_KEY;
  const key = env.CLERK_PUBLISHABLE_KEY;
  if (typeof secret !== 'string' || !/^sk_(test|live)_\S+$/.test(secret)) return null;
  if (typeof key !== 'string') return null;
  const decoded = decodePublishableKey(key);
  if (!decoded) return null;
  return { publishableKey: key, frontendApi: decoded.frontendApi };
}
