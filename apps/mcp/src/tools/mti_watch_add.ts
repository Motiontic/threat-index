import { logEvent } from '@ti/core/log';
import {
  askAlerts,
  FORM_MESSAGE,
  openState,
  readAnswer,
  sealingKey,
  sealState,
  type WatchState,
} from '../elicit';
import { mtiLink } from '../links';
import { arr, bool, obj, root, str } from '../schema';
import type { CallDeps } from '../server';
import { rec } from './common';
import { apiJson, type RunContext, type ToolAnswer, type ToolDef } from './shared';
import { parseTarget, targetPath, WATCH_INPUT, type WatchInput } from './watch-common';

const NAME = 'mti_watch_add';
const NOTE_OFF = (link: string | null) =>
  `Email alerts are off. Turn them on in MTI settings${link ? `: ${link}` : ''}.`;

type AlertsOn = boolean;

/** Reads the account's alert state. True when instant alerts or a digest are on. Never returns the address. */
async function alertsOn(deps: CallDeps, signal: AbortSignal): Promise<AlertsOn | null> {
  const me = await apiJson<unknown>(deps, { method: 'GET', path: '/v1/me' }, signal);
  if (!me.ok) return null;
  const a = rec(rec(me.body).alerts);
  return a.instant === true || (typeof a.digest === 'string' && a.digest !== 'off');
}

function result(state: WatchState, alerts: 'on' | 'off', notes: string[]): ToolAnswer {
  const t = state.target;
  return {
    ok: true,
    data: {
      watched:
        t.kind === 'package'
          ? { kind: 'package', ecosystem: t.ecosystem, name: t.name }
          : { kind: 'entry', entryId: t.entryId },
      created: state.created,
      alerts,
      notes,
    },
    nIn: 1,
    nOut: 1,
  };
}

export const tool: ToolDef<WatchInput> = {
  name: NAME,
  enabled: true,
  scope: 'mti:watch',
  hints: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  title: 'Watch a package or entry',
  description:
    "Adds one package or one entry to the user's watchlist so MTI emails alerts about it. Takes an ecosystem and name, a purl (the version is ignored) or a CVE, GHSA, OSV, MAL or EUVD ID, one item at a time. A user can watch up to 200 packages. Returns whether the watch is new and whether email alerts are on. Changes the account's watchlist.",
  inputSchema: root(WATCH_INPUT),
  outputSchema: root(
    obj({
      watched: obj(
        {
          kind: { type: 'string', enum: ['package', 'entry'] },
          ecosystem: str(40),
          name: str(214),
          entryId: str(64),
        },
        ['kind'],
      ),
      created: bool(),
      alerts: { type: 'string', enum: ['on', 'off'] },
      notes: arr(str(300), 10),
    }),
  ),
  async run(args, deps, signal, request?: RunContext) {
    const parsed = parseTarget(args);
    if (!parsed.ok) return { ok: false, code: 'invalid_argument', field: parsed.field };
    const target = parsed.target;
    const bind = { sub: deps.identity.sub, tool: NAME, args: args as Record<string, unknown> };
    const link = mtiLink(deps.env, 'account');

    // A retry: the first call already added the watch. Open the sealed state, then act on the answer.
    if (request?.requestState !== undefined) {
      const state = await openState(
        [deps.env.MCP_STATE_KEY, deps.env.MCP_STATE_KEY_NEXT],
        request.requestState,
        bind,
      );
      if (!state) return { ok: false, code: 'invalid_argument', field: 'requestState' };
      const answer = readAnswer(request.inputResponses);
      if (answer.kind === 'invalid') return { ok: false, code: 'invalid_argument', field: 'inputResponses' };
      if (answer.kind === 'off') return result(state, 'off', [NOTE_OFF(link)]);
      const patched = await apiJson<unknown>(
        deps,
        { method: 'PATCH', path: '/v1/me', body: { alerts: { digest: answer.frequency } } },
        signal,
      );
      if (patched.ok) return result(state, 'on', []);
      // Already on (or a limit): report what the account says now.
      const now = await alertsOn(deps, signal);
      return result(state, now ? 'on' : 'off', now ? [] : [NOTE_OFF(link)]);
    }

    const put = await apiJson<unknown>(deps, { method: 'PUT', path: targetPath(target), body: {} }, signal);
    if (!put.ok) return { ok: false, code: put.code, retryAfter: put.retryAfter };
    const created = rec(put.body).created === true;
    const state: WatchState = { created, target };

    const on = await alertsOn(deps, signal);
    if (on === null) return result(state, 'off', [`Email alert settings could not be checked.`]);
    if (on) return result(state, 'on', []);
    if (request?.elicitation) {
      const key = sealingKey(deps.env);
      if (!key) {
        logEvent('warn', 'mcp_state_key_missing', { requestId: deps.requestId });
      } else {
        return { ok: true, inputRequired: askAlerts(await sealState(key, bind, state)) };
      }
    }
    return result(state, 'off', [NOTE_OFF(link)]);
  },
};
