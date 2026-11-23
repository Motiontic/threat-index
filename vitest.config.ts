import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Loop worktrees are full checkouts of the repo; never run their tests from here.
    exclude: [...configDefaults.exclude, 'worktrees/**', '.loops/**'],
  },
});
