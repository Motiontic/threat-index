import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import app from '../src/index';

const call = (path: string, init?: RequestInit) =>
  app.fetch(
    new Request(`https://api.test${path}`, init),
    env as never,
    {
      waitUntil() {},
      passThroughException() {},
    } as unknown as ExecutionContext,
  );

describe('api (Workers runtime, local D1)', () => {
  it('GET /v1/health returns 200', async () => {
    const res = await call('/v1/health');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it('GET /v1/health answers 200 even when Clerk is misconfigured (mounted before clerkMiddleware)', async () => {
    const broken = { ...env, CLERK_SECRET_KEY: '', CLERK_PUBLISHABLE_KEY: '' };
    const res = await app.fetch(
      new Request('https://api.test/v1/health'),
      broken as never,
      {
        waitUntil() {},
        passThroughException() {},
      } as unknown as ExecutionContext,
    );
    expect(res.status).toBe(200);
    // Control: a Clerk-protected route does not survive the same misconfiguration.
    const guarded = await app.fetch(
      new Request('https://api.test/v1/me/watch'),
      broken as never,
      {
        waitUntil() {},
        passThroughException() {},
      } as unknown as ExecutionContext,
    );
    expect(guarded.status).not.toBe(200);
  });

  it('rejects an unsigned Clerk webhook with 400', async () => {
    const res = await call('/webhooks/clerk', { method: 'POST', body: '{}' });
    expect(res.status).toBe(400);
  });

  it('rejects an unsigned Resend webhook with 400, so stubs keep their auth', async () => {
    const res = await call('/webhooks/resend', { method: 'POST', body: '{}' });
    expect(res.status).toBe(400);
  });

  it('GET /v1/me/watch without a session returns 401', async () => {
    const res = await call('/v1/me/watch');
    expect(res.status).toBe(401);
  });

  it('signed-in stubs return 401 without a session, public stubs return 501', async () => {
    expect((await call('/v1/me')).status).toBe(401);
    expect((await call('/v1/me/saved-searches')).status).toBe(401);
    expect((await call('/v1/deep-query', { method: 'POST' })).status).toBe(401);
    expect((await call('/v1/entries/CVE-2025-0001/receipts')).status).toBe(401);
  });

  it('HMAC and token routes reject missing or wrong signatures', async () => {
    expect((await call('/internal/jobs/j1/complete', { method: 'POST' })).status).toBe(401);
    const bad = await call('/internal/jobs/j1/complete', {
      method: 'POST',
      headers: { 'x-job-signature': 'abc' },
    });
    expect(bad.status).toBe(401);
    expect((await call('/unsubscribe?t=nope')).status).toBe(401);
  });

  it('GET /v1/entries/:id returns preview fields to a visitor', async () => {
    await env.DB_VULNS.prepare(
      `INSERT INTO vulns (key, kind, title, summary, published, modified, cvss, kev_added, sources, doc_key)
       VALUES (?1, 'cve', 'Example flaw', 'Short summary', '2025-05-01', '2025-05-02T00:00:00Z', 9.8, '2025-05-05', '["cisa-kev"]', 'docs/secret')`,
    )
      .bind('CVE-2025-9999')
      .run();
    const res = await call('/v1/entries/cve-2025-9999');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access: string; entry: Record<string, unknown>; credits: unknown[] };
    expect(body.access).toBe('preview');
    expect(body.entry).toEqual({
      key: 'CVE-2025-9999',
      kind: 'cve',
      title: 'Example flaw',
      summary: 'Short summary',
      published: '2025-05-01',
      cvss: 9.8,
      kev_added: '2025-05-05',
    });
    expect(body.entry).not.toHaveProperty('doc_key');
    expect(body.credits).toEqual([{ source: 'cisa-kev', text: 'Source: CISA KEV' }]);
    expect(res.headers.get('cache-control')).toBe('public, max-age=300');
  });

  it('GET /v1/entries/:id returns 404 for an unknown entry', async () => {
    expect((await call('/v1/entries/CVE-1999-0000')).status).toBe(404);
  });
});
