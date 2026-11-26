import { logEvent } from '@ti/core/log';
import { type Ecosystem, MAX_CHECK_PACKAGES } from '@ti/core/packages';
import type { comparerFor, inRange } from '@ti/core/versions';
import { Hono } from 'hono';
import { requireUser } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { buildAnswer, emptyAnswer } from '../lib/packages-answer';
import { readCheckBody } from '../lib/packages-input';
import { loadPackageData } from '../lib/packages-lookup';
import { DEFAULT_RULES } from '../lib/packages-match';
import { chargeQuota, DAILY_PACKAGE_QUOTA, refundQuota } from '../lib/packages-quota';
import type { ReadEnv } from '../lib/preview';

export interface PackagesDeps {
  now?: () => Date;
  versions?: { inRange: typeof inRange; comparerFor: typeof comparerFor };
}

const MAX_BODY_BYTES = 1024 * 1024;

type Outcome = 'ok' | 'all_rejected' | 'quota_exceeded' | 'quota_unavailable' | 'failed';

/**
 * POST /v1/packages/check: up to 1,000 packages against MTI's own data. Stores nothing but a usage count,
 * logs only counts and timing, and makes no outbound calls: it reads D1 and the SETTINGS KV only.
 */
export function createPackagesRoute(deps: PackagesDeps = {}): Hono<AppEnv> {
  const route = new Hono<AppEnv>();
  const clock = deps.now ?? (() => new Date());
  const rules = deps.versions ?? DEFAULT_RULES;

  // Every answer, 401 included, carries no-store.
  route.use('/v1/packages/check', async (c, next) => {
    c.header('Cache-Control', 'no-store');
    await next();
    c.res.headers.set('Cache-Control', 'no-store');
  });

  route.post('/v1/packages/check', requireUser, async (c) => {
    const t0 = Date.now();
    const now = clock();
    const env = c.env as unknown as ReadEnv;
    const userId = c.get('userId');

    // Body: size, then JSON, then the envelope.
    const declared = Number(c.req.header('content-length'));
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES)
      return c.json({ error: 'body_too_large' }, 413);
    const bytes = await c.req.arrayBuffer();
    if (bytes.byteLength > MAX_BODY_BYTES) return c.json({ error: 'body_too_large' }, 413);
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      return c.json({ error: 'invalid_body' }, 400);
    }
    const read = readCheckBody(parsed);
    if (!read.ok) {
      return read.error === 'too_many_packages'
        ? c.json({ error: 'too_many_packages', max: MAX_CHECK_PACKAGES }, 400)
        : c.json({ error: 'invalid_body' }, 400);
    }
    const { entries, rejected, needsRelease } = read;

    const log = (outcome: Outcome, f: Record<string, number> = {}) =>
      logEvent('info', 'packages_check', {
        requestId: c.get('requestId'),
        outcome,
        checked: entries.length,
        matched: 0,
        rejected: rejected.length,
        uncertain: 0,
        confusion: 0,
        unknownNames: 0,
        ecosystems: 0,
        ms: Date.now() - t0,
        msQuota: 0,
        msLookup: 0,
        msMatch: 0,
        ...f,
      });

    if (entries.length === 0) {
      log('all_rejected');
      return c.json(emptyAnswer(rejected, now, needsRelease));
    }

    // Quota: fails closed.
    const tQuota = Date.now();
    let charge: Awaited<ReturnType<typeof chargeQuota>>;
    try {
      charge = await chargeQuota(env.DB_USERS, userId, entries.length, now);
    } catch {
      log('quota_unavailable', { msQuota: Date.now() - tQuota });
      c.header('Retry-After', '30');
      return c.json({ error: 'quota_unavailable' }, 503);
    }
    const msQuota = Date.now() - tQuota;
    if (!charge.ok) {
      log('quota_exceeded', { msQuota });
      c.header('Retry-After', String(charge.retryAfter));
      return c.json(
        {
          error: 'quota_exceeded',
          limit: DAILY_PACKAGE_QUOTA,
          remaining: charge.remaining,
          retryAfter: charge.retryAfter,
        },
        429,
      );
    }

    try {
      const names = new Map<Ecosystem, string[]>();
      for (const e of entries) {
        const list = names.get(e.ref.ecosystem);
        if (list) list.push(e.ref.name);
        else names.set(e.ref.ecosystem, [e.ref.name]);
      }
      const tLookup = Date.now();
      const data = await loadPackageData(env, names);
      const msLookup = Date.now() - tLookup;
      const tMatch = Date.now();
      const { response, stats } = buildAnswer({
        entries,
        rejected,
        needsRelease,
        data,
        now,
        origin: env.SITE_ORIGIN,
        rules,
      });
      log('ok', { ...stats, msQuota, msLookup, msMatch: Date.now() - tMatch });
      return c.json(response);
    } catch (err) {
      // Give the charge back, then answer like `guarded()`: the route and the error name only.
      const refund = refundQuota(env.DB_USERS, userId, entries.length, now).catch(() =>
        logEvent('error', 'packages_refund_failed'),
      );
      try {
        c.executionCtx.waitUntil(refund);
      } catch {
        await refund;
      }
      logEvent('error', 'guarded_failed', {
        requestId: c.get('requestId'),
        route: 'POST /v1/packages/check',
        name: err instanceof Error ? err.name : 'unknown',
      });
      log('failed', { msQuota });
      return c.json({ error: 'internal' }, 500);
    }
  });

  return route;
}

export default createPackagesRoute();
