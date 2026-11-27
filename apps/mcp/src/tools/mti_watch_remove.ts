import { bool, obj, root } from '../schema';
import { rec } from './common';
import { apiJson, type ToolDef } from './shared';
import { parseTarget, targetPath, WATCH_INPUT, type WatchInput } from './watch-common';

export const tool: ToolDef<WatchInput> = {
  name: 'mti_watch_remove',
  enabled: true,
  scope: 'mti:watch',
  hints: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  title: 'Stop watching',
  description:
    "Removes one package or one entry from the user's watchlist. Takes the same input as adding: an ecosystem and name, a purl or an entry ID, one item at a time. At most 20 watches can be removed through MCP in a day. Returns whether a watch was removed.",
  inputSchema: root(WATCH_INPUT),
  outputSchema: root(obj({ removed: bool() })),
  async run(args, deps, signal) {
    const parsed = parseTarget(args);
    if (!parsed.ok) return { ok: false, code: 'invalid_argument', field: parsed.field };
    const res = await apiJson<unknown>(deps, { method: 'DELETE', path: targetPath(parsed.target) }, signal);
    if (!res.ok) return { ok: false, code: res.code, retryAfter: res.retryAfter };
    return { ok: true, data: { removed: rec(res.body).removed === true }, nIn: 1, nOut: 1 };
  },
};
