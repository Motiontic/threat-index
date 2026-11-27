import { enabledTools } from './tools';
import { HINTS } from './tools/shared';

let toolsHashMemo: string | undefined;

/** First 12 hex characters of SHA-256 over the tool definitions. Constant data, computed once per isolate. */
export async function toolsHash(): Promise<string> {
  if (toolsHashMemo) return toolsHashMemo;
  const defs = enabledTools().map((t) => ({
    name: t.name,
    title: t.title,
    description: t.description,
    inputSchema: t.inputSchema,
    outputSchema: t.outputSchema,
    hints: { ...HINTS, ...t.hints },
    scope: t.scope ?? 'mti:read',
  }));
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(defs)));
  toolsHashMemo = [...new Uint8Array(d)]
    .slice(0, 6)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return toolsHashMemo;
}
