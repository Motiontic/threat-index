import { env } from 'cloudflare:workers';
import { ipKey } from '@ti/core/edge';
import { logEvent, REQUEST_ID_HEADER } from '@ti/core/log';
import { createRequestHandler } from 'react-router';
import { currentMode } from '../app/data/data.server';
import {
  applyMissingBaseHeaders,
  RATE_LIMIT_RETRY_AFTER,
  rateLimitedResponse,
  secureRedirect,
  shouldNoindex,
} from '../app/lib/security.server';
import { workersDevRedirect } from '../app/lib/site.server';

const requestHandler = createRequestHandler(
  () => import('virtual:react-router/server-build'),
  import.meta.env.MODE,
);

/** Per-IP page limit. Fails open: a missing binding or a throwing limit() lets the request through. */
async function overLimit(request: Request): Promise<boolean> {
  const ip = request.headers.get('cf-connecting-ip');
  if (!ip || !env.RL_PAGES) return false;
  try {
    return !(await env.RL_PAGES.limit({ key: `ip:${ipKey(ip)}` })).success;
  } catch {
    logEvent('warn', 'rate_limit_unavailable', { reason: 'limit_threw' });
    return false;
  }
}

export default {
  async fetch(request) {
    const started = Date.now();
    // Always a fresh id: a visitor's x-request-id is replaced, so it cannot forge a log trail.
    const requestId = crypto.randomUUID();
    const url = new URL(request.url);
    let response: Response;
    const toSite = workersDevRedirect(request, { tiEnv: env.TI_ENV, siteOrigin: env.SITE_ORIGIN });
    if (toSite) {
      response = toSite;
    } else if (await overLimit(request)) {
      response = rateLimitedResponse(url.pathname.endsWith('.data'));
    } else {
      const headers = new Headers(request.headers);
      headers.set(REQUEST_ID_HEADER, requestId);
      const handled = await requestHandler(new Request(request, { headers }));
      // Loader redirects never reach `handleRequest`; give them the document headers here.
      response = secureRedirect(handled, {
        dev: import.meta.env.DEV,
        noindex: shouldNoindex({ mode: currentMode(), tiEnv: env.TI_ENV, status: handled.status }),
      });
    }
    // Some responses (a cached or fetched one) have immutable headers: copy once if so.
    try {
      response.headers.set(REQUEST_ID_HEADER, requestId);
    } catch {
      response = new Response(response.body, response);
      response.headers.set(REQUEST_ID_HEADER, requestId);
    }
    applyMissingBaseHeaders(response.headers);
    if (response.status === 429 && !response.headers.has('Retry-After'))
      response.headers.set('Retry-After', RATE_LIMIT_RETRY_AFTER);
    logEvent('info', 'request', {
      requestId,
      method: request.method,
      path: url.pathname.slice(0, 120),
      status: response.status,
      ms: Date.now() - started,
    });
    return response;
  },
} satisfies ExportedHandler<Env>;
