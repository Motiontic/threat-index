import { globSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

/**
 * `pnpm test:workers`: tests that need the Workers runtime (workerd), with local D1, R2, KV and Queues.
 * Each app or package defines its own project in its own `vitest.workers.mts` (built with
 * test/workers-project.mts), so adding Workers tests to a package needs no edit here.
 * Run in loop sandboxes and CI, not in `pnpm build`.
 *
 * Vitest only accepts project files named `vitest.*.config.*` in a `projects` glob, so this loads each
 * `vitest.workers.mts` itself and passes the project configs inline.
 */
const root = fileURLToPath(new URL('.', import.meta.url));
const files = ['apps/*/vitest.workers.mts', 'packages/*/vitest.workers.mts']
  .flatMap((pattern) => globSync(pattern, { cwd: root }))
  .sort();

export default defineConfig({
  test: {
    // Off on purpose, same reason as vitest.config.ts: a cached transform of test/fixtures.ts hides
    // fixture files added after the cache was written.
    fsModuleCache: false,
    projects: await Promise.all(
      files.map(async (f) => (await import(new URL(f, `file://${root}`).href)).default),
    ),
  },
});
