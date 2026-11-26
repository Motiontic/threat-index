import { clerkMiddleware } from '@hono/clerk-auth';
import { logEvent } from '@ti/core/log';
import { Hono, type MiddlewareHandler } from 'hono';
import type { AppEnv } from './lib/env';
import { securityHeaders } from './lib/headers';
import { mcpIdentity } from './lib/mcp-identity';
import { rateLimit } from './lib/rate-limit';
import { requestContext } from './lib/request-context';
import adminOps from './routes/admin-ops';
import breaches from './routes/breaches';
import deepQuery from './routes/deep-query';
import entries from './routes/entries';
import health from './routes/health';
import home from './routes/home';
import incidents from './routes/incidents';
import indexLetter from './routes/index-letter';
import internalJobs from './routes/internal-jobs';
import me from './routes/me';
import meChanges from './routes/me-changes';
import packages from './routes/packages';
import savedSearches from './routes/saved-searches';
import search from './routes/search';
import sources from './routes/sources';
import techniques from './routes/techniques';
import unsubscribe from './routes/unsubscribe';
import watch from './routes/watch';
import watchPackages from './routes/watch-packages';
import webhooksClerk from './routes/webhooks-clerk';
import webhooksResend from './routes/webhooks-resend';

/**
 * ti-api. See docs/IMPLEMENTATION_PLAN.md §8. This file only builds the app: shared middleware,
 * then one module per route group in ./routes. Shared code lives in ./lib.
 * Single-user accounts: we only ever read `userId` from Clerk, never `orgId`.
 */
export function createApp(clerk: MiddlewareHandler<AppEnv> = clerkMiddleware()) {
  const app = new Hono<AppEnv>();

  // Request id and security headers wrap everything, errors and 404s included.
  app.use('*', requestContext);
  app.use('*', securityHeaders);

  app.onError((err, c) => {
    logEvent('error', 'unhandled_error', { requestId: c.get('requestId'), name: err.name });
    return c.json({ error: 'internal', requestId: c.get('requestId') }, 500);
  });
  app.notFound((c) => c.json({ error: 'not_found', requestId: c.get('requestId') }, 404));

  // Health is mounted before the Clerk middleware so it answers 200 even when Clerk is misconfigured.
  app.route('/', health);

  // Webhook, unsubscribe and internal routes are verified by signature or token, not by session,
  // so they sit outside the Clerk middleware, which covers /v1/* only.
  // A signed MCP identity (from ti-mcp) is checked first, on every path (so /internal/* and the webhooks
  // refuse it too). A call that carries one never reaches Clerk: it is either verified or refused here.
  app.use('*', mcpIdentity);
  app.use('/v1/*', (c, next) => (c.get('mcp') ? next() : clerk(c, next)));
  // Limits run after Clerk (to know the user) and before any cache. Health, webhooks and internal calls are not limited.
  app.use('/v1/*', rateLimit);
  app.use('/unsubscribe', rateLimit);

  for (const route of [
    home,
    search,
    entries,
    indexLetter,
    sources,
    breaches,
    incidents,
    techniques,
    me,
    meChanges,
    watch,
    watchPackages,
    packages,
    savedSearches,
    deepQuery,
    adminOps,
    webhooksClerk,
    webhooksResend,
    unsubscribe,
    internalJobs,
  ]) {
    app.route('/', route);
  }

  return app;
}

const app = createApp();
export default app;
