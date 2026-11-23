// How often each source cadence runs, in ms. Shared by the collector's planner and the /ops report.
// The keys are the `Cadence` union of @ti/sources/registry (core does not depend on sources).
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
export const CADENCE_MS: Record<
  '3h' | 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'with-cve-list',
  number
> = {
  '3h': 3 * HOUR,
  'with-cve-list': 3 * HOUR,
  daily: DAY,
  weekly: 7 * DAY,
  monthly: 30 * DAY,
  quarterly: 91 * DAY,
};
