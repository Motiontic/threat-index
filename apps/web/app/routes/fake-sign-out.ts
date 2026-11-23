import { env } from 'cloudflare:workers';
import { data, redirect } from 'react-router';
import { fakeAuthActive, fakeSignOutCookie } from '../lib/fake-auth.server';
import { localPath } from '../lib/redirect';
import type { Route } from './+types/fake-sign-out';

export async function loader({ request }: Route.LoaderArgs) {
  if (!fakeAuthActive(env)) throw data(null, { status: 404 });
  return redirect(localPath(new URL(request.url).searchParams.get('redirect')), {
    headers: { 'Set-Cookie': fakeSignOutCookie() },
  });
}
