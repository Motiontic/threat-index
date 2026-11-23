import { index, primaryKey, sqliteTable, text } from 'drizzle-orm/sqlite-core';

/**
 * ti_signals: exploit evidence (kept as separate kinds) and the change log that powers alerts
 * Mirrors migrations/signals/0001_init.sql. The SQL is the source of truth; every table there is
 * WITHOUT ROWID, and CHECK constraints are not modelled. A Workers test compares these columns to
 * PRAGMA table_info.
 */
export const signals = sqliteTable(
  'signals',
  {
    vulnKey: text('vuln_key').notNull(),
    kind: text('kind').notNull(),
    source: text('source').notNull(),
    ref: text('ref').notNull(),
    firstSeen: text('first_seen').notNull(),
    evidenceDate: text('evidence_date'),
    url: text('url'),
  },
  (t) => [primaryKey({ columns: [t.vulnKey, t.kind, t.source, t.ref] })],
);

export const changes = sqliteTable(
  'changes',
  {
    id: text('id').primaryKey(),
    entityKey: text('entity_key').notNull(),
    kind: text('kind').notNull(),
    old: text('old'),
    new: text('new'),
    at: text('at').notNull(),
    source: text('source'),
  },
  (t) => [index('changes_by_time').on(t.at)],
);
