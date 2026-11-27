import { canonicalEcosystem } from '@ti/core/packages';
import { CAPS, clean } from '../clean';
import { openCursor, sealCursor } from '../cursor';
import { arr, bool, int, nstr, obj, root, str } from '../schema';
import { date, ID_RE, list, matching, rec } from './common';
import { apiJson, fitToBudget, type ToolDef } from './shared';

const PAGE = 100;

type Item = {
  kind: 'entry' | 'package';
  createdAt: string;
  alertsOn: boolean;
  ecosystem?: string;
  name?: string;
  entryId?: string;
  untrusted?: { title: string | null };
};

export const tool: ToolDef<{ cursor?: string }> = {
  name: 'mti_watch_list',
  enabled: true,
  title: 'List watches',
  description:
    'Lists what the user watches, packages and entries together, newest first, with whether alerts are on for each. Entry titles come from outside sources and are returned under untrusted. Long lists come in pages.',
  inputSchema: root(obj({ cursor: str(512) }, [])),
  outputSchema: root(
    obj({
      asOf: str(40),
      total: int(),
      items: arr(
        obj(
          {
            kind: { type: 'string', enum: ['entry', 'package'] },
            createdAt: str(40),
            alertsOn: bool(),
            ecosystem: str(40),
            name: str(214),
            entryId: str(128),
            untrusted: obj({ title: nstr(CAPS.title) }),
          },
          ['kind', 'createdAt', 'alertsOn'],
        ),
        1200,
      ),
      truncated: bool(),
      nextCursor: nstr(512),
    }),
  ),
  async run(args, deps, signal) {
    let offset = 0;
    if (args.cursor !== undefined) {
      const st = await openCursor(
        [deps.env.MCP_HMAC_SECRET, deps.env.MCP_HMAC_SECRET_NEXT],
        'mti_watch_list',
        args as Record<string, unknown>,
        args.cursor,
        deps.identity.sub,
      );
      if (!st || !('o' in st)) return { ok: false, code: 'invalid_argument', field: 'cursor' };
      offset = st.o;
    }
    const [pk, en] = await Promise.all([
      apiJson<unknown>(deps, { method: 'GET', path: '/v1/me/watch/packages' }, signal),
      apiJson<unknown>(deps, { method: 'GET', path: '/v1/me/watch' }, signal),
    ]);
    if (!pk.ok) return { ok: false, code: pk.code, retryAfter: pk.retryAfter };
    if (!en.ok) return { ok: false, code: en.code, retryAfter: en.retryAfter };

    const items: Item[] = [];
    for (const v of list(rec(pk.body).items)) {
      const r = rec(v);
      const ecosystem = typeof r.ecosystem === 'string' ? canonicalEcosystem(r.ecosystem) : null;
      const created = date(r.createdAt);
      if (!ecosystem || typeof r.name !== 'string' || r.name.length > 214 || !created) continue;
      items.push({
        kind: 'package',
        createdAt: created,
        alertsOn: r.alertsOn === true,
        ecosystem,
        name: r.name,
      });
    }
    for (const v of list(rec(en.body).items)) {
      const r = rec(v);
      const entryId = matching(r.entryKey, ID_RE);
      const created = date(r.createdAt);
      if (!entryId || !created) continue;
      items.push({
        kind: 'entry',
        createdAt: created,
        alertsOn: r.alertsOn === true,
        entryId,
        untrusted: { title: clean(r.title, CAPS.title) },
      });
    }
    items.sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0));

    const page = items.slice(offset, offset + PAGE);
    const asOf = deps.now().toISOString();
    const fitted = fitToBudget({ asOf, total: items.length, items: page, truncated: false }, 'items', 600);
    const kept = fitted.kept;
    const more = offset + kept < items.length;
    const secret = deps.env.MCP_HMAC_SECRET;
    const nextCursor =
      more && secret
        ? await sealCursor(
            secret,
            'mti_watch_list',
            args as Record<string, unknown>,
            { o: offset + kept },
            deps.identity.sub,
          )
        : null;
    const data = { ...fitted.data, truncated: more, nextCursor };
    return { ok: true, data, nIn: 1, nOut: kept };
  },
};
