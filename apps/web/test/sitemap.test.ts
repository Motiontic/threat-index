import { beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ mode: 'api', sitemap: null as Response | null, throws: false }));
vi.mock('../app/data/data.server', () => ({
  getData: () => ({
    mode: state.mode,
    sitemap: async () => {
      if (state.throws) throw new Error('boom');
      return state.sitemap;
    },
  }),
}));

import { loader } from '../app/routes/sitemap';

const run = () =>
  loader({ request: new Request('https://web.test/sitemap.xml') } as never) as Promise<Response>;

describe('/sitemap.xml', () => {
  beforeEach(() => Object.assign(state, { mode: 'api', sitemap: null, throws: false }));

  it('passes XML through with its headers', async () => {
    state.sitemap = new Response('<urlset/>', { headers: { 'Content-Type': 'application/xml' } });
    const res = await run();
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('<urlset/>');
    expect(res.headers.get('Content-Type')).toBe('application/xml; charset=utf-8');
    expect(res.headers.get('Cache-Control')).toBe('public, max-age=3600');
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('is a plain-text 404 when there is no sitemap, on error, and in fixtures mode', async () => {
    for (const setup of [
      () => {},
      () => (state.throws = true),
      () => {
        state.mode = 'fixtures';
        state.sitemap = new Response('<urlset/>', { headers: { 'Content-Type': 'application/xml' } });
      },
    ]) {
      Object.assign(state, { mode: 'api', sitemap: null, throws: false });
      setup();
      const res = await run();
      expect(res.status).toBe(404);
      expect(res.headers.get('Content-Type')).toMatch(/^text\/plain/);
    }
  });
});
