import { EmptyState } from '../components/ui';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/account';

export async function loader({ request }: Route.LoaderArgs) {
  return { origin: new URL(request.url).origin };
}

export function meta({ loaderData }: Route.MetaArgs) {
  return buildMeta({
    title: pageTitle('Account'),
    description: 'Accounts are not open yet. Search and previews stay free.',
    path: '/account',
    origin: loaderData.origin,
    noindex: true,
  });
}

export default function Account() {
  return (
    <div>
      <div className="page-head">
        <h1>Account</h1>
      </div>
      <EmptyState title="Accounts aren’t open yet">
        <p>
          Accounts aren’t open yet. Sign-up with an email code, Google or GitHub comes next. Search and
          previews stay free.
        </p>
      </EmptyState>
    </div>
  );
}
