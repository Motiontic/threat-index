import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { beforeAll } from 'vitest';

/** The config passes each D1 binding's migrations in `env.MIGRATIONS`; apply them to local D1. */
beforeAll(async () => {
  const migrations = (
    env as unknown as { MIGRATIONS: Record<string, Parameters<typeof applyD1Migrations>[1]> }
  ).MIGRATIONS;
  for (const [binding, list] of Object.entries(migrations)) {
    await applyD1Migrations((env as unknown as Record<string, D1Database>)[binding] as D1Database, list);
  }
});
