import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Off on purpose: test/fixtures.ts expands `import.meta.glob('../fixtures/*/*')` when Vite transforms
    // it, and the persistent module cache (node_modules/.vitest-cache) keys that transform on the helper's
    // own content. A fixture added by a pull or rebase stayed invisible until the cache was deleted.
    // CI starts with no cache, so this makes local runs behave like CI.
    fsModuleCache: false,
    exclude: [
      ...configDefaults.exclude,
      // Loop worktrees are full checkouts of the repo; never run their tests from here.
      'worktrees/**',
      '.loops/**',
      // Need the Workers runtime: run with `pnpm test:workers`.
      '**/*.workers.test.ts',
    ],
  },
});
