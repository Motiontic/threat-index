import { secondsUntilUtcMidnight } from '@ti/core/budget';

/** Matches `max_retries` in wrangler.jsonc. Queues allow up to 100 (queues/platform/limits). */
export const LOADER_MAX_RETRIES = 10;

/** Queues allow `delaySeconds` up to 24 hours (queues/platform/limits, checked 23 Nov 2026). */
const MAX_DELAY_SECONDS = 86_400;

/** How long to hold a first-load chunk back: past the next UTC midnight, so one hop reaches the next day. */
export function deferDelaySeconds(now: Date): number {
  return Math.min(MAX_DELAY_SECONDS, secondsUntilUtcMidnight(now) + 60);
}

/** Backoff before a retry: 30 s, 60 s, 120 s … capped at an hour. `attempts` counts from 1. */
export function retryDelaySeconds(attempts: number): number {
  const n = Math.max(1, Math.floor(attempts));
  return Math.min(3600, 30 * 2 ** Math.min(n - 1, 20));
}
