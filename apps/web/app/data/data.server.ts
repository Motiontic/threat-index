// The one place loaders get data from. In api mode it calls ti-api through the `API` service binding; in
// fixtures mode it calls an in-process fake of the same routes. Only `api.server.ts` calls `fetch`.
import { env } from 'cloudflare:workers';
import { type ActionFunctionArgs, data, type LoaderFunctionArgs } from 'react-router';
import { getSession, type Session } from '../lib/auth.server';
import { ApiUnavailable, createAccountClient, createSiteData } from './api.server';
import { fixtureApi } from './fixture-api.server';
import { type DataMode, dataMode } from './mode.server';
import type { AccountClient, SiteData } from './types';

export function currentMode(): DataMode {
  return dataMode(env);
}

/** An unavailable API becomes a 502 the root error boundary renders (and hydrates with the same status). */
export async function bridge<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (err) {
    if (err instanceof ApiUnavailable) {
      console.error(err.message, err.cause);
      throw data(null, { status: 502 });
    }
    throw err;
  }
}

/** What every loader calls. `request` is not read: nothing about the visitor is forwarded to ti-api. */
export function getData(_request: Request): SiteData {
  const mode = currentMode();
  const site = createSiteData(mode === 'api' && env.API ? env.API : { fetch: fixtureFetch }, mode);
  return {
    mode,
    entry: (id) => bridge(() => site.entry(id)),
    search: (p) => bridge(() => site.search(p)),
    index: (l, c) => bridge(() => site.index(l, c)),
    sources: () => bridge(() => site.sources()),
    sitemap: () => site.sitemap(),
  };
}

const fixtureFetch = (input: RequestInfo | URL, init?: RequestInit) => fixtureApi(new Request(input, init));

/**
 * The signed-in seam: a session and an API client that carries its token as `Authorization: Bearer`, or null
 * when the visitor is signed out. Only account loaders and actions call this; `getData` above never sends auth.
 */
export async function getAccount(
  args: LoaderFunctionArgs | ActionFunctionArgs,
): Promise<{ session: Session; client: AccountClient } | null> {
  const session = await getSession(args);
  if (!session) return null;
  const api = currentMode() === 'api' && env.API ? env.API : { fetch: fixtureFetch };
  return { session, client: createAccountClient(api, session.token) };
}
