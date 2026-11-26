import type { BreachSummary, WorldList } from '@ti/core/world-api';
import { CAPS, clean } from '../clean';
import { hasBadText } from '../input';
import { mtiLink } from '../links';
import { arr, COMMON_OUT, int, nstr, obj, root, str } from '../schema';
import { credits, date, ID_RE, list, matching, rec, sources } from './common';
import { readPage, slicePage } from './paged';
import { apiJson, asOfFrom, fitToBudget, type ToolDef } from './shared';

type Args = { query?: string; limit?: number; cursor?: string };
const COMPANY_KEY = /^(cik:\d{1,10}|domain:[a-z0-9.-]{1,253})$/;
const JURISDICTION = /^[A-Za-z]{2}(-[A-Za-z0-9]{1,3})?$/;
const UNITS = ['state_residents', 'individuals', 'accounts', 'not_stated', 'claim'];

export const tool: ToolDef<Args> = {
  name: 'mti_search_breaches',
  enabled: true,
  title: 'Search breaches',
  description:
    'Searches breach notices grouped by company: notice count, affected-record counts by unit and jurisdiction, dates and sources. Company-level data only, with no personal data. Searches by company name or domain, not by email address.',
  inputSchema: root(
    obj({ query: str(100, { minLength: 1 }), limit: int({ minimum: 1, maximum: 25, default: 10 }), cursor: str(512) }, []),
  ),
  outputSchema: root(
    obj({
      ...COMMON_OUT,
      items: arr(
        obj({
          key: str(128),
          url: str(300),
          companyKey: nstr(260),
          firstSeen: nstr(40),
          dates: { type: ['object', 'null'], properties: { from: nstr(40), to: nstr(40) }, required: ['from', 'to'], additionalProperties: false },
          noticeCount: int(),
          counts: arr(
            obj({ unit: { type: 'string', enum: UNITS }, jurisdiction: nstr(8), count: { type: 'number' } }),
            50,
          ),
          jurisdictions: arr(str(8), 60),
          sources: arr(str(64), 20),
          untrusted: obj({ company: nstr(CAPS.name) }),
        }),
        25,
      ),
      truncated: { type: 'boolean' },
      nextCursor: nstr(512),
    }),
  ),
  async run(args, deps, signal) {
    const query = args.query?.normalize('NFKC').trim();
    if (query?.includes('@')) return { ok: false, code: 'invalid_argument', field: 'query', problem: 'looks_like_email' };
    if (query && hasBadText(query)) return { ok: false, code: 'invalid_argument', field: 'query', problem: 'bad_characters' };
    const limit = args.limit ?? 10;
    const at = await readPage(deps, 'mti_search_breaches', args as Record<string, unknown>);
    if (!at) return { ok: false, code: 'invalid_argument', field: 'cursor' };
    const q = new URLSearchParams();
    if (query) q.set('q', query);
    if (at.page > 1) q.set('page', String(at.page));
    const res = await apiJson<WorldList<BreachSummary>>(
      deps,
      { method: 'GET', path: `/v1/breaches${q.size ? `?${q}` : ''}` },
      signal,
    );
    if (!res.ok) return { ok: false, code: res.code, retryAfter: res.retryAfter, ...(res.code === 'invalid_argument' ? { field: 'query' } : {}) };
    const api = rec(res.body);
    const all = list(api.items).flatMap((v) => {
      const x = rec(v);
      const key = matching(x.key, ID_RE);
      const url = key ? mtiLink(deps.env, 'breach', key) : null;
      if (!key || !url) return [];
      const company = rec(x.company);
      const d = rec(x.dates);
      const from = date(d.from);
      const to = date(d.to);
      return [
        {
          key,
          url,
          companyKey: matching(company.key, COMPANY_KEY),
          firstSeen: date(x.firstSeen),
          dates: from && to ? { from, to } : null,
          noticeCount: Number.isInteger(x.noticeCount) ? (x.noticeCount as number) : 0,
          counts: list(x.counts).flatMap((c) => {
            const y = rec(c);
            if (!UNITS.includes(y.unit as string) || typeof y.count !== 'number' || !Number.isFinite(y.count)) return [];
            return [{ unit: y.unit as string, jurisdiction: matching(y.jurisdiction, JURISDICTION), count: y.count }];
          }).slice(0, 50),
          jurisdictions: list(x.jurisdictions).filter((j): j is string => typeof j === 'string' && JURISDICTION.test(j)).slice(0, 60),
          sources: sources(x.sources),
          untrusted: { company: clean(company.name, CAPS.name) },
        },
      ];
    });
    const sliced = await slicePage(deps, 'mti_search_breaches', args as Record<string, unknown>, at, all, api.next, limit);
    const fit = fitToBudget(
      { asOf: asOfFrom(undefined, deps), credits: credits(api.credits), notes: [], items: sliced.items, truncated: false, nextCursor: sliced.nextCursor },
      'items',
    );
    return { ok: true, data: fit.data, nIn: 1, nOut: fit.kept };
  },
};
