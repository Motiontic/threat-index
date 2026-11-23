// Small client pieces shared by the pages: the account fetcher and the sign-in buttons.
import type { ReactNode } from 'react';
import { Link, useFetcher } from 'react-router';
import type { ActionResult } from '../lib/account-action.server';
import { useAuthState, useOpenSignIn, useOpenSignUp } from '../lib/auth';

/** A fetcher for `/account/do`. Submits build their own body; no markup of ours posts a form. */
export function useAccountFetcher() {
  const fetcher = useFetcher<ActionResult>();
  const submit = (body: Record<string, string> | HTMLFormElement) =>
    fetcher.submit(body, { method: 'post', action: '/account/do' });
  return { fetcher, submit, result: fetcher.data, busy: fetcher.state !== 'idle' };
}

export const ERROR_TEXT: Record<string, string> = {
  limit_reached: 'You have reached the limit. Remove something first.',
  sign_in_required: 'Your session ended. Sign in again.',
  bad_origin: 'The request was refused.',
  not_found: 'That record was not found.',
  unavailable: 'The service is not answering. Try again in a moment.',
  delete_sign_in_failed: 'Your data is deleted; removing the sign-in failed, try again.',
  confirmation_mismatch: 'Type the phrase exactly.',
};
export const errorText = (code: string) =>
  ERROR_TEXT[code] ?? 'That did not work. Check the values and try again.';

/** "Sign up free" / "Log in", or a plain note when sign-in is not configured. */
export function SignInButtons({ className = '' }: { className?: string }) {
  const { available } = useAuthState();
  if (!available)
    return (
      <span className={`button button-disabled ${className}`.trim()} aria-disabled="true">
        Sign-in is unavailable
      </span>
    );
  return (
    <>
      <Link to="/sign-in" className={`button ${className}`.trim()}>
        Log in
      </Link>
      <Link to="/sign-up" className={`button button-primary ${className}`.trim()}>
        Sign up free
      </Link>
    </>
  );
}

/** Opens the sign-up (or sign-in) modal (or tells the visitor sign-in is unavailable). */
export function OpenSignUpButton({
  children,
  primary = false,
  mode = 'up',
  onBefore,
}: {
  children: ReactNode;
  primary?: boolean;
  mode?: 'up' | 'in';
  onBefore?: () => void;
}) {
  const { available } = useAuthState();
  const openUp = useOpenSignUp();
  const openIn = useOpenSignIn();
  const open = mode === 'up' ? openUp : openIn;
  if (!available)
    return (
      <button type="button" className="button button-disabled" disabled>
        Sign-in is unavailable
      </button>
    );
  return (
    <button
      type="button"
      className={primary ? 'button button-primary' : 'button'}
      onClick={() => {
        onBefore?.();
        open({ fallbackRedirectUrl: window.location.href });
      }}
    >
      {children}
    </button>
  );
}
