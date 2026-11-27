import type { McpServer } from '@modelcontextprotocol/server';
import {
  memorySkillFiles,
  type SkillCatalog,
  SkillsExtension,
} from '@modelcontextprotocol/server/ext/skills';
import { logEvent } from '@ti/core/log';
import { SKILL_FILES } from '../skills.generated';

/** How long a failed load is remembered, so a broken bundle does not rebuild and log on every request. */
export const FAILURE_TTL_MS = 60_000;

let catalogMemo: SkillCatalog | undefined;
let failedAt: number | undefined;

/** Test hook: forget the cached catalog and failure. */
export function resetSkillCatalog(): void {
  catalogMemo = undefined;
  failedAt = undefined;
}

/**
 * The catalog of bundled skills, built once per isolate. Only the resolved value is cached, never a promise,
 * so a rejected load does not stick; a failure is remembered for 60 seconds. It holds only the bundled files,
 * never anything about a user. Null when loading failed: the server then runs without skills.
 */
export async function skillCatalog(now: number = Date.now()): Promise<SkillCatalog | null> {
  if (catalogMemo) return catalogMemo;
  if (failedAt !== undefined && now - failedAt < FAILURE_TTL_MS) return null;
  try {
    const c = await SkillsExtension.load(memorySkillFiles({ ...SKILL_FILES }), {
      prefix: 'mti',
      strict: true,
      cacheHint: { ttlMs: 3_600_000, cacheScope: 'public' },
    });
    catalogMemo = c;
    failedAt = undefined;
    return c;
  } catch (e) {
    failedAt = now;
    logEvent('error', 'mcp_skills_unavailable', {
      error: e instanceof Error ? e.constructor.name : typeof e,
    });
    return null;
  }
}

/** Serves the skills on this request's server. A null catalog, or a failed attach, leaves the server without skills. */
export function register(server: McpServer, catalog: SkillCatalog | null): void {
  if (!catalog) return;
  try {
    server.server.registerCapabilities({ resources: { listChanged: false } });
    catalog.attach(server);
  } catch (e) {
    logEvent('error', 'mcp_skills_attach_failed', {
      error: e instanceof Error ? e.constructor.name : typeof e,
    });
  }
}
