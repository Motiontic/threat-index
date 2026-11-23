import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig, defineProject } from 'vitest/config';
import { writeTestConfig } from './scripts/wrangler-config.mjs';

/**
 * `pnpm test:workers`: tests that need the Workers runtime (workerd), with local D1, R2, KV and Queues.
 * One project per Worker app that has bindings. Each uses that app's wrangler.jsonc `env.staging`
 * section, with its ${VAR} placeholders filled with dummy values (never real ids).
 * Run in loop sandboxes and CI, not in `pnpm build`.
 */
/** Newest compatibility date the pool's workerd accepts. Raise it when the pool is upgraded. */
const WORKERD_MAX_COMPAT_DATE = '2026-08-22';

const MIGRATIONS = (db: string) => new URL(`./packages/db/migrations/${db}`, import.meta.url).pathname;

const ALL_DBS = {
  DB_CONTROL: 'control',
  DB_VULNS: 'vulns',
  DB_ADVISORIES: 'advisories',
  DB_SIGNALS: 'signals',
  DB_WORLD: 'world',
  DB_USERS: 'users',
};

function workerProject(
  name: string,
  app: string,
  include: string[],
  dbs: Record<string, string>,
  bindings = {},
) {
  const configPath = writeTestConfig(app);
  return defineProject({
    plugins: [
      cloudflareTest(async () => {
        const migrations: Record<string, unknown> = {};
        for (const [binding, db] of Object.entries(dbs))
          migrations[binding] = await readD1Migrations(MIGRATIONS(db));
        return {
          wrangler: { configPath, environment: 'staging' },
          miniflare: {
            // The workerd bundled with the pool is older than the apps' compatibility_date.
            compatibilityDate: WORKERD_MAX_COMPAT_DATE,
            bindings: { ...bindings, MIGRATIONS: migrations },
          },
        };
      }),
    ],
    test: { name, include, setupFiles: ['./test/setup/workers.ts'] },
  });
}

// Dummy secrets. The Clerk publishable key decodes to "example.clerk.accounts.dev$".
const API_BINDINGS = {
  CLERK_SECRET_KEY: 'sk_test_dummy',
  CLERK_PUBLISHABLE_KEY: 'pk_test_ZXhhbXBsZS5jbGVyay5hY2NvdW50cy5kZXYk',
  CLERK_WEBHOOK_SIGNING_SECRET: 'whsec_dGVzdC1zaWduaW5nLXNlY3JldA==',
  RESEND_WEBHOOK_SECRET: 'whsec_dGVzdC1yZXNlbmQtc2VjcmV0',
  UNSUBSCRIBE_SECRET: 'test-unsubscribe-secret',
  JOB_HMAC_SECRET: 'test-job-hmac-secret',
};

export default defineConfig({
  test: {
    projects: [
      workerProject('api', 'api', ['apps/api/test/**/*.workers.test.ts'], ALL_DBS, API_BINDINGS),
      workerProject('db', 'api', ['packages/db/test/**/*.workers.test.ts'], ALL_DBS, API_BINDINGS),
      workerProject('collector', 'collector', ['apps/collector/test/**/*.workers.test.ts'], {
        DB_CONTROL: 'control',
        DB_VULNS: 'vulns',
        DB_ADVISORIES: 'advisories',
        DB_SIGNALS: 'signals',
        DB_WORLD: 'world',
      }),
    ],
  },
});
