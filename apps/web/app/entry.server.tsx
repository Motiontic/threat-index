import { env } from 'cloudflare:workers';
import { isbot } from 'isbot';
import { renderToReadableStream } from 'react-dom/server';
import type { EntryContext, HandleDataRequestFunction } from 'react-router';
import { ServerRouter } from 'react-router';
import { currentMode } from './data/data.server';
import { authMode } from './lib/fake-auth.server';
import { NonceProvider } from './lib/nonce';
import { applySecurityHeaders, makeNonce, shouldNoindex } from './lib/security.server';

/** The Clerk instance host for the CSP, only when Clerk is configured and not replaced by fake auth. */
function clerkHosts() {
  const mode = authMode(env);
  return mode.kind === 'clerk' ? { frontendApi: mode.config.frontendApi } : null;
}

const noindex = (status: number) => shouldNoindex({ mode: currentMode(), tiEnv: env.TI_ENV, status });

export default async function handleRequest(
  request: Request,
  responseStatusCode: number,
  responseHeaders: Headers,
  routerContext: EntryContext,
) {
  const nonce = makeNonce();
  let status = responseStatusCode;
  const body = await renderToReadableStream(
    <NonceProvider value={nonce}>
      <ServerRouter context={routerContext} url={request.url} nonce={nonce} />
    </NonceProvider>,
    {
      nonce,
      signal: request.signal,
      onError(error: unknown) {
        console.error(error);
        status = 500;
      },
    },
  );

  // Crawlers get the whole page before any bytes are sent.
  if (isbot(request.headers.get('user-agent') ?? '')) await body.allReady;

  responseHeaders.set('Content-Type', 'text/html; charset=utf-8');
  applySecurityHeaders(responseHeaders, {
    nonce,
    dev: import.meta.env.DEV,
    noindex: noindex(status),
    clerk: clerkHosts(),
  });
  return new Response(body, { status, headers: responseHeaders });
}

/** `.data` responses (client navigations) get the same headers, without a CSP (they are not documents). */
export const handleDataRequest: HandleDataRequestFunction = (response) => {
  applySecurityHeaders(response.headers, { noindex: noindex(response.status) });
  return response;
};
