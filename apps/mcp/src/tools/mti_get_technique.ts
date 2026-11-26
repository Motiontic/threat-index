import type { TechniqueDetail } from '@ti/core/world-api';
import { CAPS, clean } from '../clean';
import { normaliseEntryId, TECHNIQUE_ID } from '../input';
import { mtiLink } from '../links';
import { arr, bool, COMMON_OUT, nstr, num, obj, root, str } from '../schema';
import { credits, ID_RE, list, matching, numOrNull, rec } from './common';
import { apiJson, asOfFrom, type ToolDef } from './shared';

const FRAMEWORKS = ['attack', 'atlas', 'cwe', 'capec'];
const ref = (extra: Record<string, unknown> = {}) =>
  obj({ id: str(32), url: nstr(300), ...extra, untrusted: obj({ name: nstr(CAPS.name) }) });

export const tool: ToolDef<{ id: string }> = {
  name: 'mti_get_technique',
  enabled: true,
  title: 'Get technique',
  description:
    'Returns one attack technique or weakness by MITRE ATT&CK, ATLAS, CWE or CAPEC ID, with its parent, sub-techniques and linked vulnerabilities.',
  inputSchema: root(obj({ id: str(32, { minLength: 3, pattern: TECHNIQUE_ID.source }) })),
  outputSchema: root(
    obj(
      {
        ...COMMON_OUT,
        found: bool(),
        id: str(32),
        framework: { type: ['string', 'null'], enum: [...FRAMEWORKS, null] },
        url: nstr(300),
        parent: { anyOf: [{ type: 'null' }, ref()] },
        children: arr(ref(), 50),
        childrenMore: bool(),
        vulns: arr(
          obj({ key: str(128), url: str(300), cvss: num(), exploited: bool(), untrusted: obj({ title: nstr(CAPS.title) }) }),
          20,
        ),
        vulnsMore: bool(),
        untrusted: obj({ name: nstr(CAPS.name), summary: nstr(CAPS.summary) }),
      },
      ['asOf', 'credits', 'notes', 'found', 'id'],
    ),
  ),
  async run(args, deps, signal) {
    const id = normaliseEntryId(args.id);
    if (!TECHNIQUE_ID.test(id)) return { ok: false, code: 'invalid_argument', field: 'id', problem: 'not_an_id' };
    const res = await apiJson<TechniqueDetail>(deps, { method: 'GET', path: `/v1/techniques/${encodeURIComponent(id)}` }, signal);
    if (!res.ok && res.status === 404)
      return { ok: true, data: { found: false, id, asOf: deps.now().toISOString(), credits: [], notes: ['No MTI record for this ID.'] }, nIn: 1, nOut: 0 };
    if (!res.ok) return { ok: false, code: res.code, retryAfter: res.retryAfter, ...(res.code === 'invalid_argument' ? { field: 'id', problem: 'not_an_id' as const } : {}) };
    const t = rec(res.body);
    const tid = (v: unknown) => matching(v, TECHNIQUE_ID);
    const link = (v: unknown) => {
      const x = tid(v);
      return x ? mtiLink(deps.env, 'technique', x) : null;
    };
    const pr = rec(t.parentRef);
    const parentId = tid(pr.id);
    const children = list(t.children).flatMap((c) => {
      const x = rec(c);
      const cid = tid(x.id);
      return cid ? [{ id: cid, url: link(cid), untrusted: { name: clean(x.name, CAPS.name) } }] : [];
    });
    const vulnsAll = list(t.vulns).flatMap((v) => {
      const x = rec(v);
      const key = matching(x.key, ID_RE);
      const url = key ? mtiLink(deps.env, 'entry', key) : null;
      return key && url ? [{ key, url, cvss: numOrNull(x.cvss), exploited: x.exploited === true, untrusted: { title: clean(x.title, CAPS.title) } }] : [];
    });
    const framework = FRAMEWORKS.find((f) => f === t.framework) ?? null;
    const data = {
      asOf: asOfFrom(undefined, deps),
      credits: credits(t.credits),
      notes: [] as string[],
      found: true,
      id,
      framework,
      url: link(id),
      parent: parentId ? { id: parentId, url: link(parentId), untrusted: { name: clean(pr.name, CAPS.name) } } : null,
      children: children.slice(0, 50),
      childrenMore: children.length > 50,
      vulns: vulnsAll.slice(0, 20),
      vulnsMore: vulnsAll.length > 20 || t.vulnsMore === true,
      untrusted: { name: clean(t.name, CAPS.name), summary: clean(t.summary, CAPS.summary) },
    };
    return { ok: true, data, nIn: 1, nOut: data.vulns.length + data.children.length };
  },
};
