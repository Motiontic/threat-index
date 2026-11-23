import { fileURLToPath } from 'node:url';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineProject } from 'vitest/config';
import { writeTestConfig } from '../../scripts/wrangler-config.mjs';
import { MIGRATIONS } from '../../test/workers-project.mts';

/**
 * The collector's Workers test project. It is `workerProject()` from test/workers-project.mts plus a stub
 * for the `API` service binding: ti-api-staging doesn't exist in the test runtime, so without a stub
 * workerd refuses to start. The tests that need ti-api use their own fakes; this stub always answers 503.
 */
const DBS = {
  DB_CONTROL: 'control',
  DB_VULNS: 'vulns',
  DB_ADVISORIES: 'advisories',
  DB_SIGNALS: 'signals',
  DB_WORLD: 'world',
};

export default defineProject({
  root: import.meta.dirname,
  plugins: [
    cloudflareTest(async () => {
      const migrations: Record<string, unknown> = {};
      for (const [binding, db] of Object.entries(DBS)) {
        migrations[binding] = await readD1Migrations(MIGRATIONS(db));
      }
      return {
        wrangler: { configPath: writeTestConfig('collector'), environment: 'staging' },
        miniflare: {
          bindings: { JOB_HMAC_SECRET: 'test-job-hmac-secret', MIGRATIONS: migrations },
          serviceBindings: { API: async () => new Response('stub', { status: 503 }) },
        },
      };
    }),
  ],
  test: {
    name: 'collector',
    include: ['test/**/*.workers.test.ts'],
    setupFiles: [fileURLToPath(new URL('../../test/setup/workers.ts', import.meta.url))],
  },
});
