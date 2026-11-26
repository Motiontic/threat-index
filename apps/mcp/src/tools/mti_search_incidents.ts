import type { IncidentSummary, WorldList } from '@ti/core/world-api';
import { CAPS, clean } from '../clean';
import { hasBadText } from '../input';
import { mtiLink, sourceLink } from '../links';
import { arr, COMMON_OUT, int, nstr, obj, root, str } from '../schema';
import { credits, date, list, matching, rec, SRC_RE } from './common';
import { readPage, slicePage } from './paged';
import { apiJson, asOfFrom, fitToBudget, type ToolDef } from './shared';

type Args = { query?: string; kind?: 'ai' | 'cyber_op' | 'cyber_event'; limit?: number; cursor?: string };
const KINDS = ['ai', 'cyber_op', 'cyber_event'];
const INCIDENT_ID = /^[\x21-\x7e]{1,128}$/;

export const tool: ToolDef<Args> = {
  name: 'mti_search_incidents',
  enabled: true,
  title: 'Search incidents',
  description:
    'Searches AI incidents and cyber operations by text and kind. Returns the date, kind and source of each incident.',
  inputSchema: root(
    obj(
      {
        query: str(100, { minLength: 1 }),
        kind: { type: 'string', enum: KINDS },
        limit: int({ minimum: 1, maximum: 25, default: 10 }),
        cursor: str(512),
      },
      [],
    ),
  ),
  outputSchema: root(
    obj({
      ...COMMON_OUT,
      items: arr(
        obj({
          source: str(64),
          incidentId: str(128),
          kind: { type: 'string', enum: KINDS },
          date: nstr(40),
          display: { type: 'string', enum: ['full', 'link'] },
          url: str(300),
          sourceUrl: nstr(2048),
          untrusted: obj({ title: nstr(CAPS.title) }),
        }),
        25,
      ),
      truncated: { type: 'boolean' },
      nextCursor: nstr(512),
    }),
  ),
  async run(args, deps, signal) {
    const query = args.query?.normalize('NFKC').trim();
    if (query && hasBadText(query))
      return { ok: false, code: 'invalid_argument', field: 'query', problem: 'bad_characters' };
    const limit = args.limit ?? 10;
    const at = await readPage(deps, 'mti_search_incidents', args as Record<string, unknown>);
    if (!at) return { ok: false, code: 'invalid_argument', field: 'cursor' };
    const q = new URLSearchParams();
    if (query) q.set('q', query);
    if (args.kind) q.set('kind', args.kind);
    if (at.page > 1) q.set('page', String(at.page));
    const res = await apiJson<WorldList<IncidentSummary>>(
      deps,
      { method: 'GET', path: `/v1/incidents${q.size ? `?${q}` : ''}` },
      signal,
    );
    if (!res.ok)
      return {
        ok: false,
        code: res.code,
        retryAfter: res.retryAfter,
        ...(res.code === 'invalid_argument' ? { field: 'query' } : {}),
      };
    const api = rec(res.body);
    const all = list(api.items).flatMap((v) => {
      const x = rec(v);
      const source = matching(x.source, SRC_RE);
      const incidentId = matching(x.incidentId, INCIDENT_ID);
      const kind = KINDS.find((k) => k === x.kind);
      const url = source && incidentId ? mtiLink(deps.env, 'incident', source, incidentId) : null;
      if (!source || !incidentId || !kind || !url) return [];
      return [
        {
          source,
          incidentId,
          kind,
          date: date(x.date),
          display: x.display === 'link' ? 'link' : 'full',
          url,
          sourceUrl: sourceLink(x.url),
          untrusted: { title: clean(x.title, CAPS.title) },
        },
      ];
    });
    const sliced = await slicePage(
      deps,
      'mti_search_incidents',
      args as Record<string, unknown>,
      at,
      all,
      api.next,
      limit,
    );
    const fit = fitToBudget(
      {
        asOf: asOfFrom(undefined, deps),
        credits: credits(api.credits),
        notes: [],
        items: sliced.items,
        truncated: false,
        nextCursor: sliced.nextCursor,
      },
      'items',
    );
    return { ok: true, data: fit.data, nIn: 1, nOut: fit.kept };
  },
};
