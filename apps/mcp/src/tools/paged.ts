import { openCursor, sealCursor } from '../cursor';
import type { CallDeps } from '../server';
import type { ToolName } from './index';

/** Reads a `{ p, k }` cursor: the API page and how many items of it were already given. */
export async function readPage(
  deps: CallDeps,
  tool: ToolName,
  args: Record<string, unknown>,
): Promise<{ page: number; skip: number } | null> {
  if (typeof args.cursor !== 'string') return { page: 1, skip: 0 };
  const st = await openCursor(
    [deps.env.MCP_HMAC_SECRET, deps.env.MCP_HMAC_SECRET_NEXT],
    tool,
    args,
    args.cursor,
    deps.identity.sub,
  );
  return st && 'p' in st ? { page: st.p, skip: st.k } : null;
}

/** Slices the API's fixed pages by `limit` and seals the cursor for what comes next. */
export async function slicePage<T>(
  deps: CallDeps,
  tool: ToolName,
  args: Record<string, unknown>,
  at: { page: number; skip: number },
  items: T[],
  apiNext: unknown,
  limit: number,
): Promise<{ items: T[]; nextCursor: string | null }> {
  const take = items.slice(at.skip, at.skip + limit);
  let state: { p: number; k: number } | null = null;
  if (at.skip + limit < items.length) state = { p: at.page, k: at.skip + limit };
  else if (typeof apiNext === 'number' && Number.isInteger(apiNext) && apiNext >= 1 && apiNext <= 40)
    state = { p: apiNext, k: 0 };
  const secret = deps.env.MCP_HMAC_SECRET;
  return {
    items: take,
    nextCursor: state && secret ? await sealCursor(secret, tool, args, state, deps.identity.sub) : null,
  };
}
