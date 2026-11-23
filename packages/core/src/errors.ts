/** Thrown by stubs (patterns, parsers, jobs, routes) that a later feature fills in. */
export class NotImplementedError extends Error {
  constructor(what: string) {
    super(`not implemented: ${what}`);
    this.name = 'NotImplementedError';
  }
}
