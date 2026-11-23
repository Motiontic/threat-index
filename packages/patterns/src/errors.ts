export type PatternErrorCode =
  // retryable
  | 'rate-limited'
  | 'timeout'
  | 'cancelled'
  | 'network'
  | 'server'
  // permanent
  | 'http'
  | 'too-large'
  | 'format'
  | 'not-configured'
  | 'request-budget'
  | 'runtime';

const RETRYABLE: ReadonlySet<PatternErrorCode> = new Set([
  'rate-limited',
  'timeout',
  'cancelled',
  'network',
  'server',
]);

/** Longest `Retry-After` we pass on. */
export const MAX_RETRY_AFTER_SECONDS = 3600;

/**
 * Thrown by every pattern. The collector reads the plain fields `code`, `retryable`, `status` and
 * `retryAfterSeconds`. Messages never contain credentials or response bodies.
 */
export class PatternError extends Error {
  readonly name = 'PatternError';
  readonly retryable: boolean;
  readonly status?: number;
  readonly retryAfterSeconds?: number;

  constructor(
    message: string,
    readonly code: PatternErrorCode,
    opts: { status?: number; retryAfterSeconds?: number; cause?: unknown } = {},
  ) {
    super(message, opts.cause === undefined ? undefined : { cause: opts.cause });
    this.retryable = RETRYABLE.has(code);
    if (opts.status !== undefined) this.status = opts.status;
    if (opts.retryAfterSeconds !== undefined)
      this.retryAfterSeconds = Math.min(
        Math.max(0, Math.ceil(opts.retryAfterSeconds)),
        MAX_RETRY_AFTER_SECONDS,
      );
  }
}
