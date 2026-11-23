// Fake sign-in for tests and QA. 404 unless fake auth is active (fixtures data and TI_ENV=local).
import { env } from 'cloudflare:workers';
import { data, redirect } from 'react-router';
import { FAKE_USER, fakeAuthActive, fakeSignInCookie } from '../lib/fake-auth.server';
import { localPath } from '../lib/redirect';
import type { Route } from './+types/fake-sign-in';

export async function loader({ request }: Route.LoaderArgs) {
  if (!fakeAuthActive(env)) throw data(null, { status: 404 });
  const url = new URL(request.url);
  const as = url.searchParams.get('as') ?? '';
  if (!FAKE_USER.test(as)) throw data(null, { status: 404 });
  return redirect(localPath(url.searchParams.get('redirect')), {
    headers: { 'Set-Cookie': fakeSignInCookie(as) },
  });
}
