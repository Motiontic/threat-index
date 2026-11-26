import { index, integer, primaryKey, sqliteTable, text } from 'drizzle-orm/sqlite-core';

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

/** migrations/advisories/0002_package_data.sql: one row per source record that names affected packages. */
export const packageAdvisories = sqliteTable(
  'package_advisories',
  {
    source: text('source').notNull(),
    sourceId: text('source_id').notNull(),
    vulnKey: text('vuln_key').notNull(),
    status: text('status').notNull().default('active'),
    summary: text('summary'),
    severity: text('severity'),
    reviewed: integer('reviewed').notNull().default(0),
    url: text('url'),
    published: text('published'),
    modified: text('modified').notNull(),
  },
  (t) => [primaryKey({ columns: [t.source, t.sourceId] }), index('package_advisories_by_vuln').on(t.vulnKey)],
);

/** migrations/advisories/0002_package_data.sql: one row per affected range (or exact-version list). */
export const affected = sqliteTable(
  'affected',
  {
    ecosystem: text('ecosystem').notNull(),
    name: text('name').notNull(),
    source: text('source').notNull(),
    sourceId: text('source_id').notNull(),
    rangeNo: integer('range_no').notNull(),
    vulnKey: text('vuln_key').notNull(),
    rangeType: text('range_type').notNull(),
    introduced: text('introduced').notNull().default('0'),
    fixed: text('fixed'),
    lastAffected: text('last_affected'),
    versions: text('versions'),
  },
  (t) => [
    primaryKey({ columns: [t.ecosystem, t.name, t.source, t.sourceId, t.rangeNo] }),
    index('affected_by_record').on(t.source, t.sourceId),
    index('affected_by_vuln').on(t.vulnKey),
  ],
);
