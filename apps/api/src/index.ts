import { clerkMiddleware } from '@hono/clerk-auth';
import { Hono } from 'hono';
import type { AppEnv } from './lib/env';
import deepQuery from './routes/deep-query';
import entries from './routes/entries';
import health from './routes/health';
import indexLetter from './routes/index-letter';
import internalJobs from './routes/internal-jobs';
import me from './routes/me';
import savedSearches from './routes/saved-searches';
import search from './routes/search';
import sources from './routes/sources';
import unsubscribe from './routes/unsubscribe';
import watch from './routes/watch';
import webhooksClerk from './routes/webhooks-clerk';
import webhooksResend from './routes/webhooks-resend';

/**
 * ti-api. See docs/IMPLEMENTATION_PLAN.md §8. This file only builds the app: shared middleware,
 * then one module per route group in ./routes. Shared code lives in ./lib.
 * Single-user accounts: we only ever read `userId` from Clerk, never `orgId`.
 */
const app = new Hono<AppEnv>();

// Webhook, unsubscribe and internal routes are verified by signature or token, not by session,
// so they sit outside the Clerk middleware, which covers /v1/* only.
app.use('/v1/*', clerkMiddleware());

for (const route of [
  health,
  search,
  entries,
  indexLetter,
  sources,
  me,
  watch,
  savedSearches,
  deepQuery,
  webhooksClerk,
  webhooksResend,
  unsubscribe,
  internalJobs,
]) {
  app.route('/', route);
}

export default app;
