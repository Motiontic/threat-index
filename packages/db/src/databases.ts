/**
 * D1 helpers. Tables use natural primary keys (WITHOUT ROWID) so one row costs one write.
 * Migrations live in ../migrations/<database>/ and are applied with `pnpm --filter @ti/db migrate:local`.
 */
export const DATABASES = [
  'ti_control',
  'ti_vulns',
  'ti_advisories',
  'ti_signals',
  'ti_world',
  'ti_users',
] as const;
export type DatabaseName = (typeof DATABASES)[number];
