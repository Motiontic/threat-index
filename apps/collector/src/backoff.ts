/** Retry delay for a failed queue message: 30 s doubling per attempt, capped at one hour. */
export function retryDelaySeconds(attempts: number): number {
  return Math.min(3600, 30 * 2 ** attempts);
}
