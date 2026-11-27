import { cvssDeliveredBy } from '@ti/core/cvss';
import type { Framework, TechniqueDetail, TechniqueSummary, WorldList } from '@ti/core/world-api';
import { Hono } from 'hono';
import { cachedPublic, guarded } from '../lib/cache';
import { creditsFor } from '../lib/credits';
import type { AppEnv } from '../lib/env';
import { displayFor } from '../lib/preview';
import {
  cacheKey,
  isListError,
  likePattern,
  optional,
  PAGE_SIZE,
  parseListQuery,
  placeholders,
  visibleSources,
  WORLD_TTL,
  type WorldEnv,
} from '../lib/world';

const route = new Hono<AppEnv>();

const FRAMEWORKS: Framework[] = ['attack', 'atlas', 'cwe', 'capec'];
const SOURCE_OF: Record<Framework, string> = {
  attack: 'mitre-attack',
  atlas: 'mitre-atlas',
  cwe: 'cwe',
  capec: 'capec',
};
const TECHNIQUE_ID = /^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?|CWE-\d{1,6}|CAPEC-\d{1,6})$/;
const CHILDREN_MAX = 200;
const VULNS_MAX = 50;

interface TechniqueRow {
  id: string;
  framework: Framework;
  name: string;
  parent: string | null;
  summary: string | null;
}

function parseFrameworks(sp: URLSearchParams): Framework[] | { error: string } {
  const out = new Set<Framework>();
  for (const f of sp.getAll('framework')) {
    if (!(FRAMEWORKS as string[]).includes(f)) return { error: 'bad_framework' };
    out.add(f as Framework);
  }
  return FRAMEWORKS.filter((f) => out.has(f));
}

function toSummary(r: TechniqueRow): TechniqueSummary {
  const out: TechniqueSummary = { id: r.id, framework: r.framework, name: r.name };
  const parent = optional(r.parent);
  if (parent !== undefined) out.parent = parent;
  return out;
}

/** Frameworks whose source is not hidden, with that source's display mode. */
async function visibleFrameworks(env: WorldEnv) {
  const display = await displayFor(env.SETTINGS, Object.values(SOURCE_OF));
  const modes = new Map<Framework, 'full' | 'link'>();
  for (const f of FRAMEWORKS) {
    const m = display.get(SOURCE_OF[f]);
    if (m === 'full' || m === 'link') modes.set(f, m);
  }
  return { display, modes };
}

route.get('/v1/techniques', (c) =>
  guarded(c, 'GET /v1/techniques', async () => {
    const env = c.env as WorldEnv;
    const query = parseListQuery(new URL(c.req.url), parseFrameworks);
    if (isListError(query)) return c.json({ error: query.error }, 400);
    const path = cacheKey('/v1/techniques', [
      ['framework', query.extra.join(',')],
      ['page', query.page],
      ['q', query.q],
    ]);
    return cachedPublic(c, WORLD_TTL, path, async () => {
      const { display, modes } = await visibleFrameworks(env);
      const wanted = (query.extra.length > 0 ? query.extra : FRAMEWORKS).filter((f) => modes.has(f));
      const body: WorldList<TechniqueSummary> = { items: [], page: query.page, next: null, credits: [] };
      if (wanted.length === 0) return c.json(body);
      const binds: (string | number)[] = [PAGE_SIZE + 1, (query.page - 1) * PAGE_SIZE, ...wanted];
      const where = [`framework IN (${placeholders(3, wanted.length)})`];
      if (query.q !== undefined) {
        where.push(
          `(id LIKE ?${3 + wanted.length} ESCAPE '\\' OR name LIKE ?${3 + wanted.length} ESCAPE '\\')`,
        );
        binds.push(likePattern(query.q));
      }
      const rows =
        (
          await env.DB_WORLD.prepare(
            `SELECT id, framework, name, parent, summary FROM techniques WHERE ${where.join(' AND ')}
             ORDER BY framework, id LIMIT ?1 OFFSET ?2`,
          )
            .bind(...binds)
            .all<TechniqueRow>()
        ).results ?? [];
      body.items = rows.slice(0, PAGE_SIZE).map(toSummary);
      body.next = rows.length > PAGE_SIZE ? query.page + 1 : null;
      body.credits = creditsFor(
        body.items.map((i) => SOURCE_OF[i.framework]),
        display,
      );
      return c.json(body);
    });
  }),
);

route.get('/v1/techniques/:id', (c) =>
  guarded(c, 'GET /v1/techniques/:id', async () => {
    const env = c.env as WorldEnv;
    const id = c.req.param('id');
    if (!TECHNIQUE_ID.test(id)) return c.json({ error: 'bad_id' }, 400);
    return cachedPublic(c, WORLD_TTL, `/v1/techniques/${encodeURIComponent(id)}`, async () => {
      const { display, modes } = await visibleFrameworks(env);
      const row = await env.DB_WORLD.prepare(
        'SELECT id, framework, name, parent, summary FROM techniques WHERE id = ?1',
      )
        .bind(id)
        .first<TechniqueRow>();
      const mode = row ? modes.get(row.framework) : undefined;
      if (!row || !mode) return c.json({ error: 'not_found' }, 404);

      const parentRow = row.parent
        ? await env.DB_WORLD.prepare(
            'SELECT id, framework, name, parent, summary FROM techniques WHERE id = ?1',
          )
            .bind(row.parent)
            .first<TechniqueRow>()
        : null;
      const children =
        (
          await env.DB_WORLD.prepare(
            `SELECT id, framework, name, parent, summary FROM techniques WHERE parent = ?1 ORDER BY id LIMIT ${CHILDREN_MAX}`,
          )
            .bind(id)
            .all<TechniqueRow>()
        ).results ?? [];
      const links =
        (
          await env.DB_WORLD.prepare(
            `SELECT vuln_key FROM vuln_techniques WHERE technique_id = ?1 ORDER BY vuln_key LIMIT ${VULNS_MAX + 1}`,
          )
            .bind(id)
            .all<{ vuln_key: string }>()
        ).results ?? [];
      const keys = links.slice(0, VULNS_MAX).map((l) => l.vuln_key);
      const vulns: TechniqueDetail['vulns'] = [];
      if (keys.length > 0) {
        const found =
          (
            await env.DB_VULNS.prepare(
              `SELECT key, title, cvss, cvss_source, cvss_from, sources, kev_added FROM vulns WHERE key IN (${placeholders(1, keys.length)})`,
            )
              .bind(...keys)
              .all<{
                key: string;
                title: string;
                cvss: number | null;
                cvss_source: string | null;
                cvss_from: string | null;
                sources: string | null;
                kev_added: string | null;
              }>()
          ).results ?? [];
        const vd = await displayFor(
          env.SETTINGS,
          found.flatMap((f) => {
            const d = cvssDeliveredBy(f);
            return d ? [d] : [];
          }),
        );
        const byKey = new Map(found.map((f) => [f.key, f]));
        for (const k of keys) {
          const f = byKey.get(k);
          if (!f) continue;
          const item: TechniqueDetail['vulns'][number] = {
            key: f.key,
            title: f.title,
            exploited: f.kev_added !== null,
          };
          const from = cvssDeliveredBy(f);
          const hidden = !from || (vd.get(from) ?? 'hidden') === 'hidden';
          if (typeof f.cvss === 'number' && !hidden) item.cvss = f.cvss;
          vulns.push(item);
        }
      }
      const detail: TechniqueDetail = {
        ...toSummary(row),
        children: children.map(toSummary),
        vulns,
        vulnsMore: links.length > VULNS_MAX,
        credits: creditsFor([SOURCE_OF[row.framework]], display),
      };
      if (mode === 'full' && row.summary) detail.summary = row.summary;
      if (parentRow && modes.has(parentRow.framework))
        detail.parentRef = { id: parentRow.id, name: parentRow.name };
      return c.json(detail);
    });
  }),
);

export default route;
