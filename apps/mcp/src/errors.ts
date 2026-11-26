/** Thrown by the stubs of features that have not landed yet. */
export class NotImplementedError extends Error {
  constructor(what: string) {
    super(`${what} is not implemented`);
    this.name = 'NotImplementedError';
  }
}
