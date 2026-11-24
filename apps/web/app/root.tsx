import { env } from 'cloudflare:workers';
import { rootAuthLoader } from '@clerk/react-router/server';
import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';
import { PRODUCT_SHORT } from '@ti/core/brand';
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
import { IntentRunner } from './components/intent-runner';
import { Shell } from './components/shell';
import { EmptyState } from './components/ui';
import { currentMode } from './data/data.server';
import { AuthProvider } from './lib/auth';
import { authMiddleware, currentAuth } from './lib/auth.server';
import { readFakeUser } from './lib/fake-auth.server';
import { useNonce } from './lib/nonce';
import { shouldNoindex } from './lib/security.server';
import { parseTheme } from './lib/theme';
import styles from './styles/app.css?url';
import tokens from './styles/tokens.css?url';

export const links: Route.LinksFunction = () => [
  { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' },
  { rel: 'stylesheet', href: tokens },
  { rel: 'stylesheet', href: styles },
];

export const middleware: Route.MiddlewareFunction[] = [authMiddleware];

export async function loader(args: Route.LoaderArgs) {
  const mode = currentMode();
  const auth = currentAuth();
  const fields = () => ({
    sourceCount: SOURCES.length,
    sample: mode === 'fixtures',
    theme: parseTheme(args.request.headers.get('Cookie')),
    noindex: shouldNoindex({ mode, tiEnv: env.TI_ENV, status: 200 }),
    auth: {
      kind: auth.kind,
      fakeUser: auth.kind === 'fake' ? readFakeUser(args.request) : null,
    },
    clerk: auth.kind === 'clerk' ? auth.config : null,
  });
  // Clerk's root loader only works once its middleware has run, i.e. when Clerk is configured.
  if (auth.kind === 'clerk') return rootAuthLoader(args, () => fields());
  return fields();
}

export function Layout({ children }: { children: React.ReactNode }) {
  const nonce = useNonce();
  // Unknown (the root loader failed): stay out of search engines.
  const root = useRouteLoaderData<typeof loader>('root');
  const noindex = root?.noindex ?? true;
  // The stored theme choice is rendered by the server, so the first paint is already right. No choice:
  // no attribute, and the CSS follows prefers-color-scheme.
  const theme = root?.theme ?? undefined;
  return (
    <html lang="en" data-theme={theme}>
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
  const data = useLoaderData<typeof loader>();
  const { sourceCount, sample, auth, theme } = data;
  return (
    <AuthProvider auth={auth} loaderData={data}>
      <Shell
        sample={sample}
        sourceCount={sourceCount}
        query={useQuery()}
        theme={theme}
        persistent={<IntentRunner />}
      >
        <Outlet />
      </Shell>
    </AuthProvider>
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
  const copy = errorCopy(status);
  const title = copy.title;
  const entryId = pathname.startsWith('/e/') ? safeDecode(pathname.slice(3)) : null;
  const searchTo = entryId ? `/search?q=${encodeURIComponent(entryId.slice(0, 200))}` : '/search';

  const page = (
    <Shell sample={root?.sample ?? true} sourceCount={root?.sourceCount ?? null} theme={root?.theme ?? null}>
      <title>{`${status === 404 ? 'Not found' : title} · ${PRODUCT_SHORT}`}</title>
      {root?.noindex === false ? <meta name="robots" content="noindex" /> : null}
      <div className="page-head">
        <h1>{title}</h1>
        <span className="error-code">{status}</span>
      </div>
      <EmptyState title={copy.heading}>
        <p>
          {copy.body}{' '}
          <Link to={searchTo}>{entryId ? `Search for “${entryId.slice(0, 80)}”` : 'Search the index'}</Link>.
        </p>
        {import.meta.env.DEV && error instanceof Error ? <pre>{error.stack}</pre> : null}
      </EmptyState>
    </Shell>
  );
  return root ? (
    <AuthProvider auth={root.auth} loaderData={root}>
      {page}
    </AuthProvider>
  ) : (
    page
  );
}

/** Error page copy by status. Anything unlisted gets the generic text. */
function errorCopy(status: number): { title: string; heading: string; body: string } {
  if (status === 404)
    return {
      title: 'Page not found',
      heading: 'We have no page here',
      body: 'The address may be wrong, or the record is not in the index.',
    };
  if (status === 429)
    return {
      title: 'Too many requests',
      heading: 'Wait a minute and try again.',
      body: 'You are going a little fast.',
    };
  if (status === 502)
    return {
      title: 'The index is not answering',
      heading: 'Records are temporarily out of reach',
      body: 'Try again in a moment.',
    };
  if (status === 500 || status === 503)
    return {
      title: 'Something went wrong on our side',
      heading: 'The page failed to load',
      body: 'Try again in a moment.',
    };
  return {
    title: 'Something went wrong',
    heading: 'The page failed to load',
    body: 'Try again in a moment.',
  };
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
