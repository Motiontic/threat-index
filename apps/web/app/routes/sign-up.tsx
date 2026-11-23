import { EmptyState } from '../components/ui';
import { SignUpForm, useAuthState, useOpenSignUp } from '../lib/auth';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/sign-up';

export async function loader({ request }: Route.LoaderArgs) {
  return { origin: new URL(request.url).origin };
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  return buildMeta({
    title: pageTitle('Sign up'),
    description: 'Sign up for a free Threat Index account.',
    path: '/sign-up',
    origin: loaderData.origin,
    noindex: true,
  });
}

export default function SignUpPage() {
  const { kind, available } = useAuthState();
  const open = useOpenSignUp();
  return (
    <div>
      <div className="page-head">
        <h1>Sign up</h1>
      </div>
      {kind === 'clerk' ? (
        <div className="clerk-slot">
          <SignUpForm routing="path" path="/sign-up" />
        </div>
      ) : available ? (
        <EmptyState title="Sign up (test mode)">
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
