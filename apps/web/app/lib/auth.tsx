// Client auth for the pages. Pages never import Clerk: they use these hooks and components, which run on Clerk,
// on the fake sign-in used by tests and QA, or on "off" (Clerk not configured: everyone is signed out).
import { ClerkProvider, Show, UserButton, useAuth, useClerk } from '@clerk/react-router';
import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from 'react';
import { clerkAppearance } from './clerk-appearance';
import { useNonce } from './nonce';

export type AuthKind = 'clerk' | 'fake' | 'off';

/** What the root loader tells the client about auth. */
export interface AuthData {
  kind: AuthKind;
  fakeUser: string | null;
}

interface AuthApi {
  kind: AuthKind;
  isLoaded: boolean;
  isSignedIn: boolean;
  /** False when sign-in is not configured: buttons say so instead of opening anything. */
  available: boolean;
  openSignUp: (options?: { fallbackRedirectUrl?: string }) => void;
  openSignIn: (options?: { fallbackRedirectUrl?: string }) => void;
  signOut: (redirectTo: string) => Promise<void>;
}

const OFF: AuthApi = {
  kind: 'off',
  isLoaded: true,
  isSignedIn: false,
  available: false,
  openSignUp: () => {},
  openSignIn: () => {},
  signOut: async () => {},
};
const AuthContext = createContext<AuthApi>(OFF);

export function useAuthState(): {
  isLoaded: boolean;
  isSignedIn: boolean;
  available: boolean;
  kind: AuthKind;
} {
  const { isLoaded, isSignedIn, available, kind } = useContext(AuthContext);
  return { isLoaded, isSignedIn, available, kind };
}
export function useOpenSignUp(): AuthApi['openSignUp'] {
  return useContext(AuthContext).openSignUp;
}
export function useOpenSignIn(): AuthApi['openSignIn'] {
  return useContext(AuthContext).openSignIn;
}
export function useSignOut(): AuthApi['signOut'] {
  return useContext(AuthContext).signOut;
}

export function WhenSignedIn({ children }: { children: ReactNode }) {
  const { isSignedIn } = useAuthState();
  return isSignedIn ? <>{children}</> : null;
}
export function WhenSignedOut({ children }: { children: ReactNode }) {
  const { isSignedIn } = useAuthState();
  return isSignedIn ? null : <>{children}</>;
}

/** Clerk's user menu, or a plain sign-out link in fake mode. */
export function AccountButton() {
  const { kind, isSignedIn } = useAuthState();
  if (!isSignedIn) return null;
  if (kind === 'clerk')
    return (
      <Show when="signed-in">
        <UserButton />
      </Show>
    );
  if (kind === 'fake')
    return (
      <a className="button" href="/__fake/sign-out">
        Sign out
      </a>
    );
  return null;
}

function currentPath(): string {
  return `${window.location.pathname}${window.location.search}`;
}
const fakeSignInHref = (redirect: string) =>
  `/__fake/sign-in?as=demo&redirect=${encodeURIComponent(redirect)}`;

function ClerkBridge({ children }: { children: ReactNode }) {
  const { isLoaded, isSignedIn } = useAuth();
  const clerk = useClerk();
  const api = useMemo<AuthApi>(
    () => ({
      kind: 'clerk',
      isLoaded,
      isSignedIn: Boolean(isSignedIn),
      available: true,
      openSignUp: (o) =>
        clerk.openSignUp({ fallbackRedirectUrl: o?.fallbackRedirectUrl ?? window.location.href }),
      openSignIn: (o) =>
        clerk.openSignIn({ fallbackRedirectUrl: o?.fallbackRedirectUrl ?? window.location.href }),
      signOut: async (redirectTo) => {
        try {
          await clerk.signOut({ redirectUrl: redirectTo });
        } catch {
          window.location.assign(redirectTo);
        }
      },
    }),
    [clerk, isLoaded, isSignedIn],
  );
  return <AuthContext.Provider value={api}>{children}</AuthContext.Provider>;
}

/** A stand-in for Clerk's modal in fake mode: one link to the fake sign-in route, and a way to close it. */
function FakeProvider({ fakeUser, children }: { fakeUser: string | null; children: ReactNode }) {
  const [redirect, setRedirect] = useState<string | null>(null);
  const open = useCallback(() => setRedirect(currentPath()), []);
  const api = useMemo<AuthApi>(
    () => ({
      kind: 'fake',
      isLoaded: true,
      isSignedIn: fakeUser !== null,
      available: true,
      openSignUp: open,
      openSignIn: open,
      signOut: async (redirectTo) => {
        window.location.assign(`/__fake/sign-out?redirect=${encodeURIComponent(redirectTo)}`);
      },
    }),
    [fakeUser, open],
  );
  return (
    <AuthContext.Provider value={api}>
      {children}
      {redirect === null ? null : (
        <div className="modal-backdrop">
          <div className="modal" role="dialog" aria-modal="true" aria-labelledby="fake-signup-title">
            <h2 id="fake-signup-title">Sign up (test mode)</h2>
            <p>Fake sign-in for tests and QA. No real account is made.</p>
            <div className="gate-actions">
              <a className="button button-primary" href={fakeSignInHref(redirect)}>
                Continue as demo
              </a>
              <button type="button" className="button" onClick={() => setRedirect(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </AuthContext.Provider>
  );
}

export { SignIn as SignInForm, SignUp as SignUpForm } from '@clerk/react-router';

export function AuthProvider({
  auth,
  loaderData,
  children,
}: {
  auth: AuthData;
  /** The whole root loader data: Clerk reads its state from it. */
  loaderData: unknown;
  children: ReactNode;
}) {
  // On the server the nonce comes from context; in the browser, from the page's own script tags.
  const nonce =
    useNonce() ||
    (typeof document === 'undefined'
      ? ''
      : (document.querySelector<HTMLScriptElement>('script[nonce]')?.nonce ?? ''));
  if (auth.kind === 'clerk') {
    return (
      <ClerkProvider
        loaderData={loaderData}
        signInUrl="/sign-in"
        signUpUrl="/sign-up"
        nonce={nonce}
        telemetry={false}
        appearance={clerkAppearance}
      >
        <ClerkBridge>{children}</ClerkBridge>
      </ClerkProvider>
    );
  }
  if (auth.kind === 'fake') return <FakeProvider fakeUser={auth.fakeUser}>{children}</FakeProvider>;
  return <AuthContext.Provider value={OFF}>{children}</AuthContext.Provider>;
}
