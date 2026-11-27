import { integer, real, sqliteTable, text } from 'drizzle-orm/sqlite-core';

/**
 * ti_vulns: one row per hot flaw (CVE ID, or the source ID when there is no CVE)
 * Mirrors migrations/vulns/0001_init.sql. The SQL is the source of truth; every table there is
 * WITHOUT ROWID, and CHECK constraints are not modelled. A Workers test compares these columns to
 * PRAGMA table_info.
 */
export const vulns = sqliteTable('vulns', {
  key: text('key').primaryKey(),
  kind: text('kind').notNull(),
  title: text('title').notNull(),
  summary: text('summary'),
  published: text('published'),
  modified: text('modified').notNull(),
  cvss: real('cvss'),
  cvssVersion: text('cvss_version'),
  cvssSource: text('cvss_source'),
  cwe: text('cwe'),
  kevAdded: text('kev_added'),
  kevDue: text('kev_due'),
  ransomware: integer('ransomware').notNull().default(0),
  exploitPublic: integer('exploit_public').notNull().default(0),
  epss: real('epss'),
  epssPct: real('epss_pct'),
  epssDate: text('epss_date'),
  epssModel: text('epss_model'),
  aiRelated: integer('ai_related').notNull().default(0),
  hot: integer('hot').notNull().default(1),
  sources: text('sources'),
  docKey: text('doc_key'),
  cvssFrom: text('cvss_from'),
});
