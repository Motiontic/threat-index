// The one place that touches Clerk on the server. Tests and fake mode swap `getSession`.
import { env } from 'cloudflare:workers';
import { clerkMiddleware, getAuth } from '@clerk/react-router/server';
import type { ActionFunctionArgs, LoaderFunctionArgs, MiddlewareFunction } from 'react-router';
import { authMode, FAKE_TOKEN_PREFIX, readFakeUser } from './fake-auth.server';

export interface Session {
  userId: string;
  token: string;
}

export const currentAuth = () => authMode(env);

/**
 * Root `middleware`: Clerk runs only when its config is valid; otherwise this does nothing. The keys are passed
 * explicitly (the SDK also reads them from `process.env`, which `nodejs_compat` fills) so the config that
 * `clerkConfig` validated is exactly the one in use.
 */
export const authMiddleware: MiddlewareFunction<Response> = async (args, next) => {
  const mode = currentAuth();
  if (mode.kind !== 'clerk') return next();
  return clerkMiddleware({
    publishableKey: mode.config.publishableKey,
    secretKey: env.CLERK_SECRET_KEY as string,
  })(args, next);
};

/** The signed-in user and a fresh session token, or null (signed out, Clerk off, or no token). */
export async function getSession(args: LoaderFunctionArgs | ActionFunctionArgs): Promise<Session | null> {
  const mode = currentAuth();
  if (mode.kind === 'fake') {
    const user = readFakeUser(args.request);
    return user ? { userId: `user_${user}`, token: `${FAKE_TOKEN_PREFIX}${user}` } : null;
  }
  if (mode.kind !== 'clerk') return null;
  const auth = await getAuth(args, { acceptsToken: 'session_token' });
  if (!auth.userId) return null;
  const token = await auth.getToken();
  return token ? { userId: auth.userId, token } : null;
}
