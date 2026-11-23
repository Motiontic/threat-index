import { index, integer, primaryKey, sqliteTable, text } from 'drizzle-orm/sqlite-core';

/**
 * ti_users: single-user accounts (Clerk user ID is the key; no organisations)
 * Mirrors migrations/users/0001_init.sql and 0002_account_settings.sql. The SQL is the source of truth; every table there is
 * WITHOUT ROWID, and CHECK constraints are not modelled. A Workers test compares these columns to
 * PRAGMA table_info.
 */
export const users = sqliteTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull(),
  name: text('name'),
  createdAt: text('created_at').notNull(),
  plan: text('plan').notNull().default('free'),
  alertFrequency: text('alert_frequency').notNull().default('daily'),
  alertTriggers: text('alert_triggers')
    .notNull()
    .default('["newly_exploited","public_exploit","epss_band","fix_released","breach_notice"]'),
  digestWeekday: integer('digest_weekday').notNull().default(1),
  emailSuppressed: integer('email_suppressed').notNull().default(0),
  deletedAt: text('deleted_at'),
  displayName: text('display_name'),
  alertInstant: integer('alert_instant').notNull().default(0),
  digest: text('digest').notNull().default('daily'),
});

export const watch = sqliteTable(
  'watch',
  {
    userId: text('user_id').notNull(),
    entryKey: text('entry_key').notNull(),
    createdAt: text('created_at').notNull(),
    alertsOn: integer('alerts_on').notNull().default(1),
  },
  (t) => [primaryKey({ columns: [t.userId, t.entryKey] }), index('watch_by_entry').on(t.entryKey)],
);

export const savedSearches = sqliteTable(
  'saved_searches',
  {
    userId: text('user_id').notNull(),
    id: text('id').notNull(),
    label: text('label').notNull(),
    query: text('query').notNull(),
    createdAt: text('created_at').notNull(),
    params: text('params').notNull().default('{}'),
    alertsOn: integer('alerts_on').notNull().default(0),
  },
  (t) => [primaryKey({ columns: [t.userId, t.id] })],
);

export const alertQueue = sqliteTable(
  'alert_queue',
  {
    userId: text('user_id').notNull(),
    changeId: text('change_id').notNull(),
    createdAt: text('created_at').notNull(),
    via: text('via').notNull().default('watch'),
  },
  (t) => [primaryKey({ columns: [t.userId, t.changeId] })],
);

export const alertsSent = sqliteTable(
  'alerts_sent',
  {
    userId: text('user_id').notNull(),
    changeId: text('change_id').notNull(),
    sentAt: text('sent_at').notNull(),
  },
  (t) => [primaryKey({ columns: [t.userId, t.changeId] })],
);

export const emailLog = sqliteTable('email_log', {
  day: text('day').primaryKey(),
  sent: integer('sent').notNull().default(0),
});

export const webhookEvents = sqliteTable('webhook_events', {
  id: text('id').primaryKey(),
  source: text('source').notNull(),
  receivedAt: text('received_at').notNull(),
});

export const notifyState = sqliteTable('notify_state', {
  name: text('name').primaryKey(),
  value: text('value').notNull(),
  updatedAt: text('updated_at').notNull(),
});

export const emailSends = sqliteTable('email_sends', {
  idemKey: text('idem_key').primaryKey(),
  kind: text('kind').notNull(),
  changeCount: integer('change_count').notNull(),
  status: text('status').notNull(),
  providerId: text('provider_id'),
  error: text('error'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
});
