import { openCursor } from '../cursor';
import { obj, root, str } from '../schema';
import { readTaskPage } from '../tasks/client';
import { DEEP_OUTPUT_SCHEMA, DEEP_TEMPLATES } from './deep-format';
import type { ToolDef } from './shared';

type Args = { template?: string; params?: Record<string, string>; cursor?: string };

/** Characters in a parameter value: the API checks each template's rules; this only bounds the size. */
const PARAM_VALUE = str(214);

/**
 * Always a task: the request pipeline (ext/tasks.ts) starts the query and answers with the task. This function
 * only serves a page of a stored result, from a `cursor`. A call without one never reaches it.
 */
export const tool: ToolDef<Args> = {
  name: 'mti_deep_query',
  enabled: true,
  title: 'Deep history query',
  description:
    'Answers one question from the history of MTI records, such as the changes to a CVE over time, the advisories for a package, EPSS score history, company breach notices or the CISA KEV additions in a date range. Needs a client that supports MCP tasks: the answer is read from the task when it finishes, which takes up to a few minutes. Rows are text from outside sources.',
  // A start needs a template; a later page needs a cursor. Clients that reject a top-level anyOf are noted in PROOF.md.
  inputSchema: root({
    ...obj(
      {
        template: { type: 'string', enum: [...DEEP_TEMPLATES] },
        params: {
          type: 'object',
          additionalProperties: false,
          maxProperties: 4,
          patternProperties: { '^[A-Za-z][A-Za-z0-9_]{0,40}$': PARAM_VALUE },
        },
        cursor: str(512),
      },
      [],
    ),
    anyOf: [{ required: ['template'] }, { required: ['cursor'] }],
  }),
  outputSchema: DEEP_OUTPUT_SCHEMA,
  scope: 'mti:read',
  hints: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  async run(args, deps) {
    if (typeof args.cursor !== 'string') return { ok: false, code: 'invalid_argument', field: 'cursor' };
    const st = await openCursor(
      [deps.env.MCP_HMAC_SECRET, deps.env.MCP_HMAC_SECRET_NEXT],
      'mti_deep_query',
      args as Record<string, unknown>,
      args.cursor,
      deps.identity.sub,
    );
    if (!st || !('t' in st)) return { ok: false, code: 'invalid_argument', field: 'cursor' };
    const data = await readTaskPage(deps.env, 'deep_query', deps.identity.sub, st.t, st.o);
    if (!data) return { ok: false, code: 'invalid_argument', field: 'cursor' };
    return { ok: true, data, nOut: (data.rows as unknown[]).length };
  },
};
