import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';

const { Hono } = await import('hono');
const { default: home } = await import('../src/routes/home');
const app = new Hono();
app.use('/v1/*', async (c, next) => {
  c.set('clerkAuth' as never, (() => ({ userId: null })) as never);
  await next();
});
app.route('/', home as never);

describe('GET /v1/home on an empty database', () => {
  it('answers 200 with zero counts and empty lists', async () => {
    const ctx = createExecutionContext();
    const res = await app.fetch(new Request('https://api.test/v1/home'), env as never, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      counts: Record<string, number>;
      lists: Record<string, unknown[]>;
      changes: unknown[];
    };
    expect(Object.values(body.counts).every((n) => n === 0)).toBe(true);
    expect(Object.values(body.lists).every((l) => l.length === 0)).toBe(true);
    expect(body.changes).toEqual([]);
    expect(res.headers.get('cache-control')).toBe('public, max-age=300');
  });
});
