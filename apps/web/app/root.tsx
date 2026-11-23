import { env } from 'cloudflare:workers';
import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';
import { SOURCES } from '@ti/sources/registry';
import {
  isRouteErrorResponse,
  Link,
  Links,
  Meta,
  Outlet,
  Scripts,
  ScrollRestoration,
  useLoaderData,
  useLocation,
  useRouteError,
  useRouteLoaderData,
} from 'react-router';
import type { Route } from './+types/root';
import { Shell } from './components/shell';
import { EmptyState } from './components/ui';
import { currentMode } from './data/data.server';
import { useNonce } from './lib/nonce';
import { shouldNoindex } from './lib/security.server';
import styles from './styles/app.css?url';
import tokens from './styles/tokens.css?url';

export const links: Route.LinksFunction = () => [
  { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' },
  { rel: 'stylesheet', href: tokens },
  { rel: 'stylesheet', href: styles },
];

export async function loader() {
  const mode = currentMode();
  return {
    sourceCount: SOURCES.length,
    sample: mode === 'fixtures',
    noindex: shouldNoindex({ mode, tiEnv: env.TI_ENV, status: 200 }),
  };
}

export function Layout({ children }: { children: React.ReactNode }) {
  const nonce = useNonce();
  // Unknown (the root loader failed): stay out of search engines.
  const noindex = useRouteLoaderData<typeof loader>('root')?.noindex ?? true;
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        {noindex ? <meta name="robots" content="noindex" /> : null}
        <Meta />
        <Links />
      </head>
      <body>
        {children}
        <ScrollRestoration nonce={nonce} />
        <Scripts nonce={nonce} />
      </body>
    </html>
  );
}

export default function App() {
  const { sourceCount, sample } = useLoaderData<typeof loader>();
  return (
    <Shell sample={sample} sourceCount={sourceCount} query={useQuery()}>
      <Outlet />
    </Shell>
  );
}

function useQuery(): string {
  const { pathname, search } = useLocation();
  return pathname === '/search' ? (new URLSearchParams(search).get('q') ?? '').slice(0, 200) : '';
}

export function ErrorBoundary() {
  const error = useRouteError();
  const root = useRouteLoaderData<typeof loader>('root');
  const { pathname } = useLocation();
  const status = isRouteErrorResponse(error) ? error.status : 500;
  const title =
    status === 404
      ? 'Page not found'
      : status === 502
        ? 'The index is not answering'
        : 'Something went wrong';
  const entryId = pathname.startsWith('/e/') ? safeDecode(pathname.slice(3)) : null;
  const searchTo = entryId ? `/search?q=${encodeURIComponent(entryId.slice(0, 200))}` : '/search';

  return (
    <Shell sample={root?.sample ?? true} sourceCount={root?.sourceCount ?? null}>
      <title>{`${status === 404 ? 'Not found' : title} · Threat Index`}</title>
      {root?.noindex === false ? <meta name="robots" content="noindex" /> : null}
      <div className="page-head">
        <h1>{title}</h1>
        <span className="error-code">{status}</span>
      </div>
      <EmptyState
        title={
          status === 404
            ? 'We have no page here'
            : status === 502
              ? 'Records are temporarily out of reach'
              : 'The page failed to load'
        }
      >
        <p>
          {status === 404
            ? 'The address may be wrong, or the record is not in the index.'
            : 'Try again in a moment.'}{' '}
          <Link to={searchTo}>{entryId ? `Search for “${entryId.slice(0, 80)}”` : 'Search the index'}</Link>.
        </p>
        {import.meta.env.DEV && error instanceof Error ? <pre>{error.stack}</pre> : null}
      </EmptyState>
    </Shell>
  );
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
