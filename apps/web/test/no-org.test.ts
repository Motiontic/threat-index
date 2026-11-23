import { describe, expect, it } from 'vitest';
import { appFiles } from './read-app';

describe('accounts are single-user', () => {
  it('never reads an organization field or API in apps/web/app', () => {
    const offenders = appFiles()
      .filter(([, text]) => /org[A-Z]/.test(text) || /organization/i.test(text))
      .map(([p]) => p);
    expect(offenders).toEqual([]);
  });
});
