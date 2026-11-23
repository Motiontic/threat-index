import type { IncidentDetail, IncidentKind, IncidentSummary, WorldList } from '@ti/core/world-api';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { Hono } from 'hono';
import { cachedPublic, guarded } from '../lib/cache';
import { creditsFor } from '../lib/credits';
import type { AppEnv } from '../lib/env';
import { displayFor, parseStringArray } from '../lib/preview';
import {
  allVisible,
  cacheKey,
  isListError,
  likePattern,
  optional,
  PAGE_SIZE,
  parseListQuery,
  placeholders,
  safeUrl,
  validPrintableId,
  visibleSources,
  WORLD_TTL,
  type WorldEnv,
} from '../lib/world';

const route = new Hono<AppEnv>();

interface IncidentRow {
  source: string;
  incident_id: string;
  kind: IncidentKind;
  title: string;
  date: string | null;
  entities: string | null;
  techniques: string | null;
  url: string | null;
}

const KINDS: IncidentKind[] = ['ai', 'cyber_op', 'cyber_event'];
const MAX_TECHNIQUES = 50;
const COLUMNS = 'source, incident_id, kind, title, date, entities, techniques, url';

function parseKinds(sp: URLSearchParams): IncidentKind[] | { error: string } {
  const out = new Set<IncidentKind>();
  for (const k of sp.getAll('kind')) {
    if (k === 'cyber') {
      out.add('cyber_op');
      out.add('cyber_event');
    } else if ((KINDS as string[]).includes(k)) out.add(k as IncidentKind);
    else return { error: 'bad_kind' };
  }
  return KINDS.filter((k) => out.has(k));
}

function summary(row: IncidentRow, mode: 'full' | 'link'): IncidentSummary {
  const out: IncidentSummary = {
    source: row.source,
    incidentId: row.incident_id,
    kind: row.kind,
    title: row.title,
    display: mode,
  };
  const date = optional(row.date);
  if (date !== undefined) out.date = date;
  const url = safeUrl(row.url);
  if (url !== undefined) out.url = url;
  return out;
}

route.get('/v1/incidents', (c) =>
  guarded(c, 'GET /v1/incidents', async () => {
    const env = c.env as WorldEnv;
    const query = parseListQuery(new URL(c.req.url), parseKinds);
    if (isListError(query)) return c.json({ error: query.error }, 400);
    const kinds = query.extra;
    const path = cacheKey('/v1/incidents', [
      ['kind', kinds.join(',')],
      ['page', query.page],
      ['q', query.q],
    ]);
    return cachedPublic(c, WORLD_TTL, path, async () => {
      const v = await visibleSources(env);
      const ids = allVisible(v);
      const empty: WorldList<IncidentSummary> = { items: [], page: query.page, next: null, credits: [] };
      if (ids.length === 0) return c.json(empty);
      const binds: (string | number)[] = [PAGE_SIZE + 1, (query.page - 1) * PAGE_SIZE];
      let n = 3;
      const where = ['gated = 0', `source IN (${placeholders(n, ids.length)})`];
      binds.push(...ids);
      n += ids.length;
      if (kinds.length > 0) {
        where.push(`kind IN (${placeholders(n, kinds.length)})`);
        binds.push(...kinds);
        n += kinds.length;
      }
      if (query.q !== undefined) {
        where.push(`title LIKE ?${n} ESCAPE '\\'`);
        binds.push(likePattern(query.q));
      }
      const rows =
        (
          await env.DB_WORLD.prepare(
            `SELECT ${COLUMNS} FROM incidents WHERE ${where.join(' AND ')}
             ORDER BY date IS NULL, date DESC, source, incident_id LIMIT ?1 OFFSET ?2`,
          )
            .bind(...binds)
            .all<IncidentRow>()
        ).results ?? [];
      const page = rows.slice(0, PAGE_SIZE);
      const items = page.map((r) => summary(r, v.full.includes(r.source) ? 'full' : 'link'));
      const display = await displayFor(env.SETTINGS, ids);
      const body: WorldList<IncidentSummary> = {
        items,
        page: query.page,
        next: rows.length > PAGE_SIZE ? query.page + 1 : null,
        credits: creditsFor(
          items.map((i) => i.source),
          display,
        ),
      };
      return c.json(body);
    });
  }),
);

route.get('/v1/incidents/:source/:id', (c) =>
  guarded(c, 'GET /v1/incidents/:source/:id', async () => {
    const env = c.env as WorldEnv;
    const source = c.req.param('source');
    const id = c.req.param('id');
    if (!SOURCE_BY_ID.has(source) || !validPrintableId(id)) return c.json({ error: 'bad_id' }, 400);
    const path = `/v1/incidents/${encodeURIComponent(source)}/${encodeURIComponent(id)}`;
    return cachedPublic(c, WORLD_TTL, path, async () => {
      const v = await visibleSources(env);
      const mode = v.full.includes(source) ? 'full' : v.link.includes(source) ? 'link' : null;
      if (!mode) return c.json({ error: 'not_found' }, 404);
      const row = await env.DB_WORLD.prepare(
        `SELECT ${COLUMNS} FROM incidents WHERE source = ?1 AND incident_id = ?2 AND gated = 0`,
      )
        .bind(source, id)
        .first<IncidentRow>();
      if (!row) return c.json({ error: 'not_found' }, 404);
      const base = summary(row, mode);
      const detail: IncidentDetail = { ...base, entities: [], techniques: [], credits: [] };
      const display = await displayFor(env.SETTINGS, [source]);
      detail.credits = creditsFor([source], display);
      if (mode === 'full') {
        detail.entities = parseStringArray(row.entities).slice(0, 200);
        const ids = parseStringArray(row.techniques).slice(0, MAX_TECHNIQUES);
        const names = new Map<string, string>();
        if (ids.length > 0) {
          const found =
            (
              await env.DB_WORLD.prepare(
                `SELECT id, name FROM techniques WHERE id IN (${placeholders(1, ids.length)})`,
              )
                .bind(...ids)
                .all<{ id: string; name: string }>()
            ).results ?? [];
          for (const t of found) names.set(t.id, t.name);
        }
        detail.techniques = ids.map((tid) => {
          const name = names.get(tid);
          return name === undefined ? { id: tid } : { id: tid, name };
        });
      }
      return c.json(detail);
    });
  }),
);

export default route;
