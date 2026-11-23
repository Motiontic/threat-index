import { afterEach, describe, expect, it, vi } from 'vitest';

// Spec §1: does the E2B SDK load and make its calls under workerd? Fetch is stubbed; nothing leaves the test.
afterEach(() => vi.restoreAllMocks());

describe('e2b SDK under workerd', () => {
  it('imports, creates a sandbox and starts a background command', async () => {
    const seen: { method: string; url: string }[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const req = new Request(input as RequestInfo, init);
      seen.push({ method: req.method, url: req.url });
      if (new URL(req.url).pathname === '/v2/sandboxes')
        return Response.json(
          {
            sandboxID: 'sbx123',
            templateID: 't',
            clientID: 'c',
            envdVersion: '0.2.0',
            domain: 'e2b.app',
          },
          { status: 201 },
        );
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    });
    const { Sandbox } = await import('e2b');
    const sbx = await Sandbox.create('tmpl', { apiKey: 'e2b_dummy', timeoutMs: 60_000 });
    expect(sbx.sandboxId).toBeTruthy();
    let err: unknown;
    try {
      const h = await sbx.commands.run('true', { background: true, timeoutMs: 0 });
      await h.disconnect();
    } catch (e) {
      err = e;
    }
    console.log('SEEN', JSON.stringify(seen), 'ERR', String(err));
    expect(seen[0]).toEqual({ method: 'POST', url: 'https://api.e2b.app/v2/sandboxes' });
    expect(seen.some((s) => s.url.endsWith('/process.Process/Start'))).toBe(true);
    expect(String(err)).not.toMatch(/node:|http2|eval|new Function|Cannot find module/i);
  });
});
