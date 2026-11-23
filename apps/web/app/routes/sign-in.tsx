import { EmptyState } from '../components/ui';
import { SignInForm, useAuthState, useOpenSignIn } from '../lib/auth';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/sign-in';

export async function loader({ request }: Route.LoaderArgs) {
  return { origin: new URL(request.url).origin };
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  return buildMeta({
    title: pageTitle('Log in'),
    description: 'Log in to Threat Index.',
    path: '/sign-in',
    origin: loaderData.origin,
    noindex: true,
  });
}

export default function SignInPage() {
  const { kind, available } = useAuthState();
  const open = useOpenSignIn();
  return (
    <div>
      <div className="page-head">
        <h1>Log in</h1>
      </div>
      {kind === 'clerk' ? (
        <div className="clerk-slot">
          <SignInForm routing="path" path="/sign-in" />
        </div>
      ) : available ? (
        <EmptyState title="Log in (test mode)">
          <p>
            <button type="button" className="button button-primary" onClick={() => open()}>
              Continue
            </button>
          </p>
        </EmptyState>
      ) : (
        <EmptyState title="Sign-in is unavailable">
          <p>Accounts are not connected on this site right now. Search and previews stay free.</p>
        </EmptyState>
      )}
    </div>
  );
}
