// Fake sign-in for tests and QA. It exists only when the site serves fixtures AND TI_ENV is `local`; in any
// other deploy `AUTH_MODE=fake` is ignored (and logged once). Clerk is not loaded in fake mode.
import { type ClerkConfig, clerkConfig } from './clerk-config.server';
import { dataMode } from '../data/mode.server';

export const FAKE_COOKIE = 'ti_fake_user';
export const FAKE_USER = /^[a-z0-9]{1,20}$/;
export const FAKE_TOKEN_PREFIX = 'fake.';

interface AuthEnv {
  AUTH_MODE?: string;
  DATA_SOURCE?: string;
  API?: Fetcher;
  TI_ENV?: string;
  CLERK_PUBLISHABLE_KEY?: string;
  CLERK_SECRET_KEY?: string;
}

let warned = false;
export function resetFakeAuthWarning(): void {
  warned = false;
}

export function fakeAuthActive(env: AuthEnv): boolean {
  if (env.AUTH_MODE !== 'fake') return false;
  if (dataMode(env) === 'fixtures' && env.TI_ENV === 'local') return true;
  if (!warned) {
    warned = true;
    console.error('AUTH_MODE=fake ignored: it needs fixtures data and TI_ENV=local');
  }
  return false;
}

export type AuthMode = { kind: 'fake' } | { kind: 'clerk'; config: ClerkConfig } | { kind: 'off' };

export function authMode(env: AuthEnv): AuthMode {
  if (fakeAuthActive(env)) return { kind: 'fake' };
  const config = clerkConfig(env);
  return config ? { kind: 'clerk', config } : { kind: 'off' };
}

export function readFakeUser(request: Request): string | null {
  const header = request.headers.get('cookie') ?? '';
  for (const part of header.split(';')) {
    const at = part.indexOf('=');
    if (at < 0 || part.slice(0, at).trim() !== FAKE_COOKIE) continue;
    const value = part.slice(at + 1).trim();
    return FAKE_USER.test(value) ? value : null;
  }
  return null;
}

export const fakeSignInCookie = (user: string) =>
  `${FAKE_COOKIE}=${user}; Path=/; HttpOnly; SameSite=Lax`;
export const fakeSignOutCookie = () => `${FAKE_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
