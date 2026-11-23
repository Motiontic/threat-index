// Runs the intent a visitor left before signing in (watch, save a search, open a tab), once, after sign-in.
import { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate, useRevalidator, useSearchParams } from 'react-router';
import { useAuthState } from '../lib/auth';
import { takeIntent } from '../lib/intent';
import { errorText, useAccountFetcher } from './account-bits';

export function IntentRunner() {
  const { isLoaded, isSignedIn } = useAuthState();
  const navigate = useNavigate();
  const revalidator = useRevalidator();
  const { fetcher, submit, result } = useAccountFetcher();
  const [status, setStatus] = useState<string | null>(null);
  const ran = useRef(false);
  const pending = useRef<string | null>(null);
  const { pathname } = useLocation();
  const [params] = useSearchParams();

  useEffect(() => {
    if (!isLoaded || !isSignedIn || ran.current) return;
    // `ran` also stops StrictMode's second effect run from taking (and losing) the intent again.
    ran.current = true;
    const intent = takeIntent();
    if (!intent) return;
    void (async () => {
      await revalidator.revalidate();
      if (intent.action === 'watch') {
        pending.current = `Watching ${intent.target}`;
        submit({ intent: 'watch', id: intent.target });
      } else if (intent.action === 'save-search') {
        pending.current = 'Search saved';
        submit({ intent: 'save-search', qs: intent.target });
      } else {
        const [key, tab] = intent.target.split('#');
        void navigate(`/e/${encodeURIComponent(key ?? '')}?tab=${encodeURIComponent(tab ?? '')}`);
      }
    })();
  }, [isLoaded, isSignedIn, navigate, revalidator, submit]);

  useEffect(() => {
    if (!result || !pending.current) return;
    setStatus(result.ok ? pending.current : errorText(result.error));
    pending.current = null;
  }, [result]);

  const deleted = pathname === '/' && params.get('deleted') === '1';
  const text = deleted ? 'Your account was deleted.' : status;
  if (!text) return null;
  return (
    <p className="notice" role="status" data-busy={fetcher.state !== 'idle'}>
      {text}
    </p>
  );
}
