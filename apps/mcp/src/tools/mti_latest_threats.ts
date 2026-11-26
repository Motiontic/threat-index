import type { HomeResponse } from '@ti/core/api';
import { CAPS, clean } from '../clean';
import { mtiLink } from '../links';
import { arr, COMMON_OUT, nstr, obj, root, str } from '../schema';
import { credits, date, ID_RE, list, matching, rec, SRC_RE } from './common';
import { apiJson, asOfFrom, fitToBudget, type ToolDef } from './shared';

const KINDS = {
  exploited: 'exploited',
  vulnerabilities: 'vulnerabilities',
  exploits: 'exploits',
  malicious: 'maliciousPackages',
  breaches: 'breaches',
  ai: 'aiIncidents',
} as const;
type Kind = keyof typeof KINDS;

export const tool: ToolDef<{ kind: Kind }> = {
  name: 'mti_latest_threats',
  enabled: true,
  title: 'Latest threats',
  description:
    'Lists the newest items in one category: newly exploited vulnerabilities, new vulnerabilities, new public exploits, malicious packages, breaches or AI incidents.',
  inputSchema: root(obj({ kind: { type: 'string', enum: Object.keys(KINDS) } })),
  outputSchema: root(
    obj({
      ...COMMON_OUT,
      kind: { type: 'string', enum: Object.keys(KINDS) },
      items: arr(
        obj({
          key: str(128),
          type: { type: 'string', enum: ['vuln', 'breach', 'ai', 'mal'] },
          date: nstr(40),
          url: str(300),
          signal: nstr(60),
          untrusted: obj({ title: nstr(CAPS.title) }),
        }),
        50,
      ),
      truncated: { type: 'boolean' },
    }),
  ),
  async run(args, deps, signal) {
    const apiKey = KINDS[args.kind];
    if (!apiKey) return { ok: false, code: 'invalid_argument', field: 'kind' };
    const res = await apiJson<HomeResponse>(deps, { method: 'GET', path: '/v1/home' }, signal);
    if (!res.ok) return { ok: false, code: res.code, retryAfter: res.retryAfter };
    const lists = rec(rec(res.body).lists);
    const items = list(lists[apiKey])
      .flatMap((v) => {
        const x = rec(v);
        const key = matching(x.key, ID_RE);
        const type = ['vuln', 'breach', 'ai', 'mal'].find((t) => t === x.type) as
          | 'vuln'
          | 'breach'
          | 'ai'
          | 'mal'
          | undefined;
        if (!key || !type) return [];
        let url: string | null = null;
        if (type === 'vuln' || type === 'mal') url = mtiLink(deps.env, 'entry', key);
        else if (type === 'breach') url = mtiLink(deps.env, 'breach', key);
        else {
          const src = matching(x.source, SRC_RE);
          url = src ? mtiLink(deps.env, 'incident', src, key) : null;
        }
        if (!url) return [];
        return [
          {
            key,
            type,
            date: date(x.date),
            url,
            signal: clean(x.signal, 60),
            untrusted: { title: clean(x.title, CAPS.title) },
          },
        ];
      })
      .slice(0, 50);
    const fit = fitToBudget(
      {
        asOf: asOfFrom(undefined, deps),
        credits: credits(undefined),
        notes: [],
        kind: args.kind,
        items,
        truncated: false,
      },
      'items',
    );
    return { ok: true, data: fit.data, nIn: 1, nOut: fit.kept };
  },
};
