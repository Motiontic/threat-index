import { NotImplementedError } from '@ti/core/errors';
import { expect, it } from 'vitest';
import { link } from './link';

it('link() is a stub until the linker feature fills it in', async () => {
  const deps = {
    read: async () => [],
    lookupCold: async () => null,
    now: () => new Date(),
    newId: () => 'id',
  };
  await expect(link([], deps)).rejects.toBeInstanceOf(NotImplementedError);
});
