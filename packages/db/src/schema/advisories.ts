import { index, primaryKey, sqliteTable, text } from 'drizzle-orm/sqlite-core';

/**
 * ti_advisories: every source record; doubles as the alias map (any ID -> vuln_key)
 * Mirrors migrations/advisories/0001_init.sql. The SQL is the source of truth; every table there is
 * WITHOUT ROWID, and CHECK constraints are not modelled. A Workers test compares these columns to
 * PRAGMA table_info.
 */
export const advisories = sqliteTable(
  'advisories',
  {
    source: text('source').notNull(),
    sourceId: text('source_id').notNull(),
    vulnKey: text('vuln_key'),
    status: text('status').notNull().default('active'),
    published: text('published'),
    modified: text('modified').notNull(),
    url: text('url'),
    licence: text('licence'),
  },
  (t) => [primaryKey({ columns: [t.source, t.sourceId] }), index('advisories_by_vuln').on(t.vulnKey)],
);
