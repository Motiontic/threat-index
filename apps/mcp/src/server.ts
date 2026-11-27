import { McpServer } from '@modelcontextprotocol/server';
import { CfWorkerJsonSchemaValidator } from '@modelcontextprotocol/server/validators/cf-worker';
import type { McpIdentity } from '@ti/core/mcp-user';
import { SERVER_INFO, TOOLS_LIST_CACHE } from './config';
import type { Env } from './env';
import { register as registerApps } from './ext/apps';
import { register as registerListen } from './ext/listen';
import { register as registerSkills, skillCatalog } from './ext/skills';
import { register as registerTasks, capability as tasksCapability } from './ext/tasks';
import { register as registerUploads } from './ext/uploads';
import { MAX_TOOL_INPUT_ELEMENTS } from './http/body';
import { INSTRUCTIONS } from './instructions';
import { enabledTools, type ToolName } from './tools';
import { registerTool, type ToolErrorCode } from './tools/shared';

export interface CallStats {
  tool?: string;
  nIn?: number;
  nOut?: number;
  toolError?: ToolErrorCode;
  ecosystems?: string;
}
export interface CallDeps {
  env: Env;
  identity: McpIdentity;
  requestId: string;
  signal: AbortSignal;
  stats: CallStats;
  now: () => Date;
}
export type { ToolName };

/** A fresh server for one request. Nothing here outlives it. */
export async function buildServer(deps: CallDeps): Promise<McpServer> {
  const catalog = await skillCatalog();
  const server = new McpServer(SERVER_INFO, {
    instructions: INSTRUCTIONS,
    capabilities: { tools: { listChanged: false }, extensions: { ...tasksCapability() } },
    cacheHints: { 'tools/list': TOOLS_LIST_CACHE },
    jsonSchemaValidator: new CfWorkerJsonSchemaValidator({ draft: '2020-12' }),
    maxToolInputElements: MAX_TOOL_INPUT_ELEMENTS,
  });
  for (const def of enabledTools()) registerTool(server, def, deps);
  registerSkills(server, catalog);
  registerTasks();
  registerListen();
  registerApps();
  registerUploads();
  return server;
}
