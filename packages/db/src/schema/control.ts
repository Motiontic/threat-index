import { index, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';

/**
 * ti_control: sources, bookmarks, runs, E2B jobs, budget meter
 * Mirrors migrations/control/0001_init.sql. The SQL is the source of truth; every table there is
 * WITHOUT ROWID, and CHECK constraints are not modelled. A Workers test compares these columns to
 * PRAGMA table_info.
 */
export const sources = sqliteTable('sources', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  pattern: text('pattern').notNull(),
  cadence: text('cadence').notNull(),
  licence: text('licence').notNull(),
  ingest: integer('ingest').notNull().default(1),
  display: text('display').notNull().default('full'),
  credit: text('credit'),
  homepage: text('homepage'),
  updatedAt: text('updated_at').notNull(),
});

export const cursors = sqliteTable('cursors', {
  sourceId: text('source_id').primaryKey(),
  kind: text('kind').notNull(),
  value: text('value'),
  etag: text('etag'),
  updatedAt: text('updated_at').notNull(),
});

export const runs = sqliteTable(
  'runs',
  {
    id: text('id').primaryKey(),
    sourceId: text('source_id').notNull(),
    startedAt: text('started_at').notNull(),
    finishedAt: text('finished_at'),
    status: text('status').notNull(),
    found: integer('found').notNull().default(0),
    written: integer('written').notNull().default(0),
    bytes: integer('bytes').notNull().default(0),
    error: text('error'),
  },
  (t) => [index('runs_by_source').on(t.sourceId, t.startedAt)],
);

export const jobs = sqliteTable('jobs', {
  id: text('id').primaryKey(),
  kind: text('kind').notNull(),
  sourceId: text('source_id'),
  status: text('status').notNull(),
  sandboxId: text('sandbox_id'),
  createdAt: text('created_at').notNull(),
  finishedAt: text('finished_at'),
  manifestKey: text('manifest_key'),
  error: text('error'),
});

export const budget = sqliteTable('budget', {
  day: text('day').primaryKey(),
  d1Writes: integer('d1_writes').notNull().default(0),
  queueOps: integer('queue_ops').notNull().default(0),
  r2ClassA: integer('r2_class_a').notNull().default(0),
  emailsSent: integer('emails_sent').notNull().default(0),
});
