// Resource route for every account mutation. The logic and its checks live in lib/account-action.server.ts.
import { data } from 'react-router';
import { getAccount } from '../data/data.server';
import { handleAccountAction } from '../lib/account-action.server';
import type { Route } from './+types/account-do';

export async function loader() {
  return new Response(null, { status: 405, headers: { Allow: 'POST' } });
}

export async function action(args: Route.ActionArgs) {
  const result = await handleAccountAction(args.request, {
    getClient: async () => (await getAccount(args))?.client ?? null,
  });
  return data(result, { status: result.ok ? 200 : result.status });
}
