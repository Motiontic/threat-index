import type { SourcesResponse } from '@ti/core/api';
import { CAPS, clean } from '../clean';
import { arr, nstr, obj, root, str } from '../schema';
import { date, list, matching, rec, SRC_RE } from './common';
import { apiJson, asOfFrom, type ToolDef } from './shared';

export const tool: ToolDef<Record<string, never>> = {
  name: 'mti_list_sources',
  enabled: true,
  title: 'List sources',
  description:
    'Lists the sources MTI collects from that have records: what each gives, how often it is collected, its licence status and its last successful collection.',
  inputSchema: root({ type: 'object', properties: {}, additionalProperties: false }),
  outputSchema: root(
    obj({
      asOf: str(40),
      notes: arr(str(200), 10),
      sources: arr(
        obj({
          id: str(64),
          name: nstr(CAPS.name),
          gives: nstr(CAPS.summary),
          cadence: nstr(CAPS.short),
          licence: { type: 'string', enum: ['on', 'ask', 'wait', 'link'] },
          display: { type: 'string', enum: ['full', 'link'] },
          credit: nstr(CAPS.summary),
          lastSuccess: str(40),
          lastRunStatus: nstr(32),
        }),
        200,
      ),
    }),
  ),
  async run(_args, deps, signal) {
    const res = await apiJson<SourcesResponse>(deps, { method: 'GET', path: '/v1/sources' }, signal);
    if (!res.ok) return { ok: false, code: res.code, retryAfter: res.retryAfter };
    const sources = list(rec(res.body).sources).flatMap((v) => {
      const s = rec(v);
      const id = matching(s.id, SRC_RE);
      const lastSuccess = date(s.lastSuccess);
      const licence = ['on', 'ask', 'wait', 'link'].find((l) => l === s.licence) as 'on' | 'ask' | 'wait' | 'link' | undefined;
      if (!id || !lastSuccess || !licence || (s.display !== 'full' && s.display !== 'link')) return [];
      return [
        {
          id,
          name: clean(s.name, CAPS.name),
          gives: clean(s.gives, CAPS.summary),
          cadence: clean(s.cadence, CAPS.short),
          licence,
          display: s.display as 'full' | 'link',
          credit: clean(s.credit, CAPS.summary),
          lastSuccess,
          lastRunStatus: matching(s.lastRunStatus, /^[a-z_]{1,32}$/),
        },
      ];
    }).slice(0, 200);
    return { ok: true, data: { asOf: asOfFrom(undefined, deps), notes: [], sources }, nIn: 1, nOut: sources.length };
  },
};
