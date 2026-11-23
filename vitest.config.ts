import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
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
