import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';

interface Migration {
  name: string;
  queries: string[];
}
const all = env as unknown as {
  MIGRATIONS: Record<string, Migration[]>;
  DB_SIGNALS: D1Database;
  DB_CONTROL: D1Database;
};
const find = (db: string, prefix: string) => {
  const m = all.MIGRATIONS[db]?.find((x) => x.name.startsWith(prefix));
  if (!m) throw new Error(`no ${db} migration ${prefix}`);
  return m.queries;
};
const insert = (id: string, extra = '') =>
  all.DB_SIGNALS.prepare(
    `INSERT INTO changes (id, entity_key, kind, old, new, at, source${extra ? ', quiet' : ''}) VALUES (?1,'CVE-2026-1','public_exploit',NULL,NULL,'2026-11-26T00:00:00Z','osv'${extra ? `, '${extra}'` : ''})`,
  )
    .bind(id)
    .run();

describe('signals 0004_change_quiet', () => {
  it('applies on top of existing rows, which read as quiet null with no event_at', async () => {
    // Put `changes` back as 0003 left it, with a row in it, then apply 0004.
    await all.DB_SIGNALS.prepare('DROP TABLE changes').run();
    await all.DB_SIGNALS.exec(
      'CREATE TABLE changes (id TEXT PRIMARY KEY, entity_key TEXT NOT NULL, kind TEXT NOT NULL, old TEXT, new TEXT, at TEXT NOT NULL, source TEXT) WITHOUT ROWID',
    );
    await all.DB_SIGNALS.prepare(
      "INSERT INTO changes (id, entity_key, kind, at) VALUES ('old1','K','public_exploit','2026-11-26T00:00:00Z')",
    ).run();
    await all.DB_SIGNALS.batch(find('DB_SIGNALS', '0004').map((q) => all.DB_SIGNALS.prepare(q)));
    const row = await all.DB_SIGNALS.prepare("SELECT event_at, quiet FROM changes WHERE id = 'old1'").first();
    expect(row).toEqual({ event_at: null, quiet: null });
  });

  it('checks the reason, and the partial index serves the alert read', async () => {
    await insert('q1', 'held');
    await expect(insert('q2', 'nonsense')).rejects.toThrow(/CHECK/i);
    const plan = (
      await all.DB_SIGNALS.prepare(
        'EXPLAIN QUERY PLAN SELECT id FROM changes WHERE quiet IS NULL AND at > ?1 ORDER BY at, id LIMIT 10',
      )
        .bind('2026-01-01')
        .all<{ detail: string }>()
    ).results
      .map((r) => r.detail)
      .join(' ');
    expect(plan).toContain('changes_alerts');
  });
});

describe('control 0002_run_alerts', () => {
  it('runs.alerts defaults to 0 for existing and new rows', async () => {
    await all.DB_CONTROL.prepare(
      "INSERT INTO runs (id, source_id, started_at, status) VALUES ('r1','s','2026-11-26T00:00:00Z','ok')",
    ).run();
    const row = await all.DB_CONTROL.prepare("SELECT alerts FROM runs WHERE id = 'r1'").first();
    expect(row).toEqual({ alerts: 0 });
    await all.DB_CONTROL.prepare("DELETE FROM runs WHERE id = 'r1'").run();
  });
});
