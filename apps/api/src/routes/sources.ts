import type { SourceStatus, SourcesResponse } from '@ti/core/api';
import { SOURCES } from '@ti/sources/registry';
import { Hono } from 'hono';
import { cachedPublic, guarded } from '../lib/cache';
import type { AppEnv } from '../lib/env';
import { displayFor, type ReadEnv } from '../lib/preview';

const route = new Hono<AppEnv>();

const SOURCES_TTL = 60;

// Public. `wait` sources are listed as hidden: their name and status show, their data does not.
route.get('/v1/sources', (c) =>
  guarded(c, 'GET /v1/sources', () =>
    cachedPublic(c, SOURCES_TTL, '/v1/sources', async () => {
      const env = c.env as ReadEnv;
      const [display, success, latest] = await Promise.all([
        displayFor(
          env.SETTINGS,
          SOURCES.map((s) => s.id),
        ),
        env.DB_CONTROL.prepare(
          "SELECT source_id, MAX(finished_at) AS last_success FROM runs WHERE status IN ('ok','unchanged') GROUP BY source_id",
        ).all<{ source_id: string; last_success: string | null }>(),
        // Bare columns with MAX() take the values of the row holding the maximum.
        env.DB_CONTROL.prepare(
          'SELECT source_id, status, MAX(started_at) AS started FROM runs GROUP BY source_id',
        ).all<{ source_id: string; status: string }>(),
      ]);
      const lastSuccess = new Map(success.results.map((r) => [r.source_id, r.last_success]));
      const lastStatus = new Map(latest.results.map((r) => [r.source_id, r.status]));
      const sources: SourceStatus[] = SOURCES.map((s) => {
        const out: SourceStatus = {
          id: s.id,
          name: s.name,
          gives: s.gives,
          pattern: s.pattern,
          cadence: s.cadence,
          licence: s.licence,
          display: display.get(s.id) ?? 'hidden',
          credit: s.credit,
        };
        const ok = lastSuccess.get(s.id);
        if (ok) out.lastSuccess = ok;
        const status = lastStatus.get(s.id);
        if (status) out.lastRunStatus = status;
        return out;
      });
      const body: SourcesResponse = { sources };
      return c.json(body);
    }),
  ),
);

export default route;
