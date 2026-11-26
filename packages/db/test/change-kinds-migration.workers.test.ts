import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';

interface Migration {
  name: string;
  queries: string[];
}
const migrations = (env as unknown as { MIGRATIONS: Record<string, Migration[]> }).MIGRATIONS
  .DB_SIGNALS as Migration[];
const db = (env as unknown as { DB_SIGNALS: D1Database }).DB_SIGNALS;

const queriesOf = (name: string) => {
  const m = migrations.find((x) => x.name.startsWith(name));
  if (!m) throw new Error(`no signals migration ${name}`);
  return m.queries;
};
const run = (queries: string[]) => db.batch(queries.map((q) => db.prepare(q)));
const insert = (id: string, kind: string) =>
  db
    .prepare(
      `INSERT INTO changes (id, entity_key, kind, old, new, at, source) VALUES (?1, 'CVE-2026-1', ?2, 'a', 'b', '2026-11-26T00:00:00Z', 'osv')`,
    )
    .bind(id, kind)
    .run();

describe('signals 0003_change_kinds', () => {
  it('keeps every row of `changes`, and then allows a new_advisory row', async () => {
    // Put `changes` back as 0001 made it (the setup has applied everything), with rows in it.
    await db.prepare('DROP TABLE changes').run();
    await run(queriesOf('0001').filter((q) => /\bchanges\b/.test(q)));
    await insert('c1', 'newly_exploited');
    await insert('c2', 'breach_notice');
    await insert('c3', 'epss_band');
    await expect(insert('c4', 'new_advisory')).rejects.toThrow(/CHECK/i);
    const before = (await db.prepare('SELECT * FROM changes ORDER BY id').all()).results;
    expect(before).toHaveLength(3);

    await run(queriesOf('0003'));

    const after = (await db.prepare('SELECT * FROM changes ORDER BY id').all()).results;
    expect(after).toEqual(before);
    await insert('c4', 'new_advisory');
    expect(
      (await db.prepare("SELECT kind FROM changes WHERE id = 'c4'").first<{ kind: string }>())?.kind,
    ).toBe('new_advisory');
    await expect(insert('c5', 'nonsense')).rejects.toThrow(/CHECK/i);
  });

  it('leaves the table and its time index as 0001 and 0002 defined them, with no temporary table behind', async () => {
    const names = (
      await db
        .prepare("SELECT name FROM sqlite_master WHERE name LIKE 'changes%' ORDER BY name")
        .all<{ name: string }>()
    ).results.map((r) => r.name);
    expect(names).toEqual(['changes', 'changes_by_time']);
    const cols = (await db.prepare('PRAGMA table_info(changes)').all<{ name: string; pk: number }>()).results;
    expect(cols.map((c) => c.name)).toEqual(['id', 'entity_key', 'kind', 'old', 'new', 'at', 'source']);
    expect(cols.filter((c) => c.pk > 0).map((c) => c.name)).toEqual(['id']);
  });

  it('the package-data and MCP tables exist with their keys', async () => {
    const users = (env as unknown as { DB_USERS: D1Database }).DB_USERS;
    const adv = (env as unknown as { DB_ADVISORIES: D1Database }).DB_ADVISORIES;
    const pk = async (d: D1Database, t: string) =>
      (await d.prepare(`PRAGMA table_info(${t})`).all<{ name: string; pk: number }>()).results
        .filter((c) => c.pk > 0)
        .sort((a, b) => a.pk - b.pk)
        .map((c) => c.name);
    expect(await pk(adv, 'package_advisories')).toEqual(['source', 'source_id']);
    expect(await pk(adv, 'affected')).toEqual(['ecosystem', 'name', 'source', 'source_id', 'range_no']);
    expect(await pk(users, 'watch_packages')).toEqual(['user_id', 'ecosystem', 'name']);
    expect(await pk(users, 'package_usage')).toEqual(['user_id', 'day']);
    expect(await pk(users, 'mcp_blocks')).toEqual(['kind', 'id']);
    await expect(
      users
        .prepare(`INSERT INTO mcp_blocks (kind, id, reason, created_at) VALUES ('team', 'x', 'abuse', 'now')`)
        .run(),
    ).rejects.toThrow(/CHECK/i);
    await expect(
      users
        .prepare(
          `INSERT INTO mcp_blocks (kind, id, reason, created_at) VALUES ('user', 'x', 'because', 'now')`,
        )
        .run(),
    ).rejects.toThrow(/CHECK/i);
    await expect(
      adv
        .prepare(
          `INSERT INTO affected (ecosystem, name, source, source_id, range_no, vuln_key, range_type) VALUES ('npm','a','s','i',0,'k','WRONG')`,
        )
        .run(),
    ).rejects.toThrow(/CHECK/i);
  });
});
