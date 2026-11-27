import type { McpServer } from '@modelcontextprotocol/server';
import {
  memorySkillFiles,
  type SkillCatalog,
  SkillsExtension,
} from '@modelcontextprotocol/server/ext/skills';
import { logEvent } from '@ti/core/log';
import { SKILL_FILES } from '../skills.generated';

let catalogMemo: SkillCatalog | null | undefined;

/**
 * The catalog of bundled skills, built once per isolate. Only the resolved value is cached, never a promise,
 * so a rejected load does not stick. It holds only the bundled files, never anything about a user.
 * Null when loading failed: the server then runs without skills.
 */
export async function skillCatalog(): Promise<SkillCatalog | null> {
  if (catalogMemo !== undefined) return catalogMemo;
  try {
    const c = await SkillsExtension.load(memorySkillFiles({ ...SKILL_FILES }), {
      prefix: 'mti',
      strict: true,
      cacheHint: { ttlMs: 3_600_000, cacheScope: 'public' },
    });
    catalogMemo = c;
    return c;
  } catch {
    logEvent('error', 'mcp_skills_unavailable');
    return null;
  }
}

/** Serves the skills on this request's server. A null catalog leaves the server without skills. */
export function register(server: McpServer, catalog: SkillCatalog | null): void {
  if (!catalog) return;
  server.server.registerCapabilities({ resources: { listChanged: false } });
  catalog.attach(server);
}
