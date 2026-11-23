import { NotImplementedError } from '@ti/core/errors';

/** Retrying cannot help: the step fails its run and the message is acked. */
export class PermanentError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PermanentError';
  }
}

/** Stubs (so they don't burn retries), our own PermanentError, Zod errors and pattern errors with `retryable: false`. */
export function isPermanent(err: unknown): boolean {
  return (
    err instanceof PermanentError ||
    err instanceof NotImplementedError ||
    (err instanceof Error && err.name === 'ZodError') ||
    // a pattern error that says retrying cannot help (`cancelled` and other retryable codes are retried)
    (typeof err === 'object' && err !== null && (err as { retryable?: unknown }).retryable === false)
  );
}

/** A pattern that has no pull config for its source yet. */
export function isNotConfigured(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === 'not-configured';
}

const MAX_ERROR_CHARS = 500;

/** `name: message` with URL query strings removed (they can carry keys), at most 500 characters. */
export function describeError(err: unknown): string {
  const name = err instanceof Error ? err.name : 'Error';
  const message = err instanceof Error ? err.message : String(err);
  const text = `${name}: ${message}`.replace(/(https?:\/\/[^\s?#"'<>)]*)[?#][^\s"'<>)]*/g, '$1');
  return text.length > MAX_ERROR_CHARS ? `${text.slice(0, MAX_ERROR_CHARS - 1)}…` : text;
}
