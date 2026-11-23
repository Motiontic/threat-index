import { describe, expect, it, vi } from 'vitest';
import { ApiBadRequest, ApiUnavailable } from '../app/data/api.server';

// A plain function, not vi.fn(): vitest reports an error thrown inside a mock as a test failure.
const state = vi.hoisted(() => ({ error: null as Error | null }));
vi.mock('../app/data/data.server', () => ({
  getData: () => ({
    index: async () => {
      if (state.error) throw state.error;
      return null;
    },
  }),
}));

import { loader } from '../app/routes/index-az';

const run = (letter: string, query = '') =>
  loader({
    request: new Request(`https://web.test/index/${letter}${query}`),
    params: { letter },
  } as never);

describe('index-az loader', () => {
  it('shows the empty state, keeping the cursor, when ti-api rejects the cursor', async () => {
    state.error = new ApiBadRequest('bad cursor');
    expect(await run('c', '?cursor=expired_1')).toMatchObject({
      letter: 'c',
      items: [],
      next: null,
      cursor: 'expired_1',
    });
  });

  it('still surfaces an unavailable API', async () => {
    state.error = new ApiUnavailable('down');
    await expect(run('c')).rejects.toBeInstanceOf(ApiUnavailable);
  });
});
