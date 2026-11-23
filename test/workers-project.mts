import { fileURLToPath } from 'node:url';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineProject } from 'vitest/config';
import { writeTestConfig } from '../scripts/wrangler-config.mjs';

/**
 * Builds one Workers test project (see vitest.workers.config.mts). Each app or package keeps its own
 * `vitest.workers.mts` that calls this with its directory (`import.meta.dirname`, the project root that
 * `include` is relative to), its bindings and dummy secrets. The project uses that app's
 * wrangler.jsonc `env.staging` section, with its ${VAR} placeholders filled with dummy values.
 */
const path = (rel: string) => fileURLToPath(new URL(rel, import.meta.url));

export const MIGRATIONS = (db: string) => path(`../packages/db/migrations/${db}`);

/** Binding name → database directory under packages/db/migrations. */
export const ALL_DBS = {
  DB_CONTROL: 'control',
  DB_VULNS: 'vulns',
  DB_ADVISORIES: 'advisories',
  DB_SIGNALS: 'signals',
  DB_WORLD: 'world',
  DB_USERS: 'users',
};

export function workerProject(
  dir: string,
  name: string,
  app: string,
  include: string[],
  dbs: Record<string, string>,
  bindings = {},
) {
  const configPath = writeTestConfig(app);
  return defineProject({
    root: dir,
    plugins: [
      cloudflareTest(async () => {
        const migrations: Record<string, unknown> = {};
        for (const [binding, db] of Object.entries(dbs))
          migrations[binding] = await readD1Migrations(MIGRATIONS(db));
        return {
          wrangler: { configPath, environment: 'staging' },
          miniflare: {
            bindings: { ...bindings, MIGRATIONS: migrations },
          },
        };
      }),
    ],
    test: { name, include, setupFiles: [path('./setup/workers.ts')] },
  });
}
