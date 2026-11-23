import { index, integer, primaryKey, real, sqliteTable, text } from 'drizzle-orm/sqlite-core';

/**
 * ti_world: techniques and weaknesses, companies, breaches, incidents
 * Mirrors migrations/world/0001_init.sql. The SQL is the source of truth; every table there is
 * WITHOUT ROWID, and CHECK constraints are not modelled. A Workers test compares these columns to
 * PRAGMA table_info.
 */
export const techniques = sqliteTable('techniques', {
  id: text('id').primaryKey(),
  framework: text('framework').notNull(),
  name: text('name').notNull(),
  parent: text('parent'),
  summary: text('summary'),
});

export const vulnTechniques = sqliteTable(
  'vuln_techniques',
  {
    vulnKey: text('vuln_key').notNull(),
    techniqueId: text('technique_id').notNull(),
    origin: text('origin').notNull().default('source'),
  },
  (t) => [primaryKey({ columns: [t.vulnKey, t.techniqueId] })],
);

export const companies = sqliteTable('companies', {
  key: text('key').primaryKey(),
  name: text('name').notNull(),
  cik: text('cik'),
  domain: text('domain'),
  ticker: text('ticker'),
  sector: text('sector'),
  aliases: text('aliases'),
});

export const breachNotices = sqliteTable(
  'breach_notices',
  {
    source: text('source').notNull(),
    noticeId: text('notice_id').notNull(),
    companyKey: text('company_key'),
    rawName: text('raw_name').notNull(),
    occurredFrom: text('occurred_from'),
    occurredTo: text('occurred_to'),
    discovered: text('discovered'),
    notified: text('notified'),
    count: integer('count'),
    countUnit: text('count_unit').notNull(),
    jurisdiction: text('jurisdiction'),
    dataTypes: text('data_types'),
    url: text('url'),
    eventKey: text('event_key'),
    modified: text('modified').notNull(),
    nameKey: text('name_key'),
  },
  (t) => [
    primaryKey({ columns: [t.source, t.noticeId] }),
    index('notices_by_company').on(t.companyKey),
    index('notices_by_name').on(t.nameKey),
  ],
);

export const breachEvents = sqliteTable('breach_events', {
  key: text('key').primaryKey(),
  companyKey: text('company_key'),
  firstSeen: text('first_seen').notNull(),
  dates: text('dates'),
  countsByUnit: text('counts_by_unit'),
  noticeCount: integer('notice_count').notNull().default(1),
  confidence: real('confidence'),
  modified: text('modified').notNull(),
});

export const incidents = sqliteTable(
  'incidents',
  {
    source: text('source').notNull(),
    incidentId: text('incident_id').notNull(),
    kind: text('kind').notNull(),
    title: text('title').notNull(),
    date: text('date'),
    entities: text('entities'),
    techniques: text('techniques'),
    url: text('url'),
    gated: integer('gated').notNull().default(0),
    modified: text('modified').notNull(),
  },
  (t) => [primaryKey({ columns: [t.source, t.incidentId] })],
);
