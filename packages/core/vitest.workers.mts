import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineProject } from 'vitest/config';

/**
 * Workers tests for @ti/core: the versions benchmark. It needs no bindings. Same compatibility date and
 * flags as the collector (apps/collector/wrangler.jsonc).
 */
export default defineProject({
  root: import.meta.dirname,
  plugins: [
    cloudflareTest({
      miniflare: { compatibilityDate: '2026-11-01', compatibilityFlags: ['nodejs_compat'] },
    }),
  ],
  test: { name: 'core', include: ['src/**/*.workers.test.ts'] },
});
