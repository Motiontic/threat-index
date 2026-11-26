import type { SearchResponse } from '@ti/core/api';
import { CAPS, clean } from '../clean';
import { openCursor, sealCursor } from '../cursor';
import { mtiLink } from '../links';
import { arr, bool, COMMON_OUT, int, nstr, num, obj, root, str } from '../schema';
import { credits, date, ID_RE, list, matching, numOrNull, rec } from './common';
import { apiJson, asOfFrom, fitToBudget, type ToolDef } from './shared';

type Args = { query: string; kind?: 'vulnerability' | 'malicious'; exploitedOnly?: boolean; limit?: number; cursor?: string };

export const tool: ToolDef<Args> = {
  name: 'mti_search',
  enabled: true,
  title: 'Search records',
  description:
    'Full-text search over MTI vulnerability and malicious-package records, with filters for kind and for exploitation in the wild. Returns up to 20 hits per page and a cursor for the next page.',
  inputSchema: root(
    obj(
      {
        query: str(200, { minLength: 1 }),
        kind: { type: 'string', enum: ['vulnerability', 'malicious'] },
        exploitedOnly: bool(),
        limit: int({ minimum: 1, maximum: 20, default: 10 }),
        cursor: str(512),
      },
      ['query'],
    ),
  ),
  outputSchema: root(
    obj({
      ...COMMON_OUT,
      total: int(),
      hits: arr(
        obj({
          key: str(128),
          url: str(300),
          cvss: num(),
          exploited: bool(),
          published: nstr(40),
          untrusted: obj({ title: nstr(CAPS.title), summary: nstr(CAPS.summary) }),
        }),
        20,
      ),
      truncated: bool(),
      nextCursor: nstr(512),
    }),
  ),
  async run(args, deps, signal) {
    const query = args.query.normalize('NFKC').trim();
    if (!query || query.length > 200) return { ok: false, code: 'invalid_argument', field: 'query' };
    const limit = args.limit ?? 10;
    const secrets = [deps.env.MCP_HMAC_SECRET, deps.env.MCP_HMAC_SECRET_NEXT];
    const q = new URLSearchParams({ q: query });
    if (args.kind) q.set('type', args.kind === 'vulnerability' ? 'vuln' : 'mal');
    if (args.exploitedOnly) q.set('sig', 'kev');
    q.set('limit', String(limit));
    if (args.cursor !== undefined) {
      const st = await openCursor(secrets, 'mti_search', args as Record<string, unknown>, args.cursor);
      if (!st || !('c' in st)) return { ok: false, code: 'invalid_argument', field: 'cursor' };
      q.set('cursor', st.c);
    }
    const res = await apiJson<SearchResponse>(deps, { method: 'GET', path: `/v1/search?${q}` }, signal);
    if (!res.ok) return { ok: false, code: res.code, retryAfter: res.retryAfter, ...(res.code === 'invalid_argument' ? { field: 'query' } : {}) };
    const api = rec(res.body);
    const hits = list(api.hits).flatMap((h) => {
      const x = rec(h);
      const key = matching(x.key, ID_RE);
      const url = key ? mtiLink(deps.env, 'entry', key) : null;
      if (!key || !url) return [];
      return [{ key, url, cvss: numOrNull(x.cvss), exploited: x.exploited === true, published: date(x.published), untrusted: { title: clean(x.title, CAPS.title), summary: clean(x.summary, CAPS.summary) } }];
    }).slice(0, limit);
    const apiCursor = matching(api.cursor, /^[A-Za-z0-9_-]{1,200}$/);
    const nextCursor = apiCursor && deps.env.MCP_HMAC_SECRET
      ? await sealCursor(deps.env.MCP_HMAC_SECRET, 'mti_search', args as Record<string, unknown>, { c: apiCursor })
      : null;
    const fit = fitToBudget(
      { asOf: asOfFrom(undefined, deps), credits: credits(api.credits), notes: [], total: Number.isInteger(api.total) ? (api.total as number) : hits.length, hits, truncated: false, nextCursor },
      'hits',
    );
    return { ok: true, data: fit.data, nIn: 1, nOut: fit.kept };
  },
};
