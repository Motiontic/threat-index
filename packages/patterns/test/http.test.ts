import { describe, expect, it } from 'vitest';
import { PatternError } from '../src/errors';
import { MAX_REQUESTS_PER_STEP, request, validatorOf } from '../src/http';
import { sourceWith } from './examples';
import { makeCtx, NOW, reply, route } from './helpers';

const URL1 = 'https://example.test/data';
const source = sourceWith('cisa-advisories');

async function failure(p: Promise<unknown>): Promise<PatternError> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(PatternError);
    return e as PatternError;
  }
  throw new Error('expected a PatternError');
}

describe('request', () => {
  it('always sends the user agent, and refuses an empty one', async () => {
    const h = makeCtx({ source, routes: [route(URL1, reply('ok'))] });
    await request(h.ctx, URL1);
    expect(h.requests[0]?.headers['user-agent']).toBe('threat-index-test/1.0 (ops@example.test)');
    const empty = makeCtx({ source, userAgent: ' ', routes: [route(URL1, reply('ok'))] });
    expect((await failure(request(empty.ctx, URL1))).code).toBe('runtime');
    expect(empty.requests).toHaveLength(0);
  });

  it('picks the ETag, else Last-Modified, as the validator and sends it back', async () => {
    expect(validatorOf(new Headers({ etag: '"a"', 'last-modified': 'x' }))).toBe('"a"');
    expect(validatorOf(new Headers({ 'last-modified': 'Thu, 01 May 2025 00:00:00 GMT' }))).toBe(
      'lm:Thu, 01 May 2025 00:00:00 GMT',
    );
    expect(validatorOf(new Headers())).toBeNull();
    const h = makeCtx({ source, routes: [route(URL1, reply('ok'))] });
    await request(h.ctx, URL1, { validator: '"a"' });
    await request(h.ctx, URL1, { validator: 'lm:Thu, 01 May 2025 00:00:00 GMT' });
    expect(h.requests[0]?.headers['if-none-match']).toBe('"a"');
    expect(h.requests[1]?.headers['if-modified-since']).toBe('Thu, 01 May 2025 00:00:00 GMT');
  });

  it('reports a 304 as notModified', async () => {
    const h = makeCtx({ source, routes: [route(URL1, reply(null, 304))] });
    const r = await request(h.ctx, URL1, { validator: '"a"' });
    expect(r.notModified).toBe(true);
    expect(r.validator).toBe('"a"');
    expect(r.text).toBe('');
  });

  it('sends Range and reads a 206; an ignored Range is cut to the range length', async () => {
    const h = makeCtx({
      source,
      routes: [
        route('https://example.test/p', reply('0123456789', 206, { 'content-range': 'bytes 0-9/100' })),
        route('https://example.test/full', reply('x'.repeat(100))),
      ],
    });
    const part = await request(h.ctx, 'https://example.test/p', { range: { start: 0, end: 9 } });
    expect(h.requests[0]?.headers.range).toBe('bytes=0-9');
    expect(part).toMatchObject({ status: 206, text: '0123456789', truncated: false });
    const cut = await request(h.ctx, 'https://example.test/full', { range: { start: 0, end: 15 } });
    expect(cut).toMatchObject({ status: 200, truncated: true });
    expect(cut.text).toHaveLength(16);
  });

  it('waits and retries once on Retry-After: 2', async () => {
    let n = 0;
    const h = makeCtx({
      source,
      routes: [
        route(URL1, () =>
          n++ === 0
            ? new Response('', { status: 429, headers: { 'retry-after': '2' } })
            : new Response('fine'),
        ),
      ],
    });
    expect((await request(h.ctx, URL1)).text).toBe('fine');
    expect(h.waits).toEqual([2000]);
    expect(h.requests).toHaveLength(2);
  });

  it('does not wait for Retry-After: 120; it throws rate-limited', async () => {
    const h = makeCtx({ source, routes: [route(URL1, reply('', 429, { 'retry-after': '120' }))] });
    const e = await failure(request(h.ctx, URL1));
    expect(e).toMatchObject({ code: 'rate-limited', retryable: true, retryAfterSeconds: 120, status: 429 });
    expect(h.waits).toEqual([]);
  });

  it('caps retryAfterSeconds at 3600 and reads an HTTP date', async () => {
    const h = makeCtx({ source, routes: [route(URL1, reply('', 429, { 'retry-after': '99999' }))] });
    expect((await failure(request(h.ctx, URL1))).retryAfterSeconds).toBe(3600);
    const date = new Date(NOW.getTime() + 5000).toUTCString();
    let n = 0;
    const h2 = makeCtx({
      source,
      routes: [
        route(URL1, () =>
          n++ === 0
            ? new Response('', { status: 503, headers: { 'retry-after': date } })
            : new Response('ok'),
        ),
      ],
    });
    await request(h2.ctx, URL1);
    expect(h2.waits).toEqual([5000]);
  });

  it('treats a GitHub 403 with x-ratelimit-remaining: 0 as a rate limit, using x-ratelimit-reset', async () => {
    const reset = String(NOW.getTime() / 1000 + 1800);
    const h = makeCtx({
      source,
      routes: [route(URL1, reply('', 403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': reset }))],
    });
    const e = await failure(request(h.ctx, URL1));
    expect(e).toMatchObject({ code: 'rate-limited', retryAfterSeconds: 1800 });
    const plain403 = makeCtx({ source, routes: [route(URL1, reply('', 403))] });
    expect(await failure(request(plain403.ctx, URL1))).toMatchObject({ code: 'http', retryable: false });
  });

  it('503 waits 60 s by default (so it is rate-limited); 500 is server; 404 is http', async () => {
    const a = makeCtx({ source, routes: [route(URL1, reply('', 503))] });
    expect(await failure(request(a.ctx, URL1))).toMatchObject({
      code: 'rate-limited',
      retryAfterSeconds: 60,
    });
    const b = makeCtx({ source, routes: [route(URL1, reply('', 500))] });
    expect(await failure(request(b.ctx, URL1))).toMatchObject({
      code: 'server',
      retryable: true,
      status: 500,
    });
    const c = makeCtx({ source, routes: [route(URL1, reply('', 404))] });
    expect(await failure(request(c.ctx, URL1))).toMatchObject({
      code: 'http',
      retryable: false,
      status: 404,
    });
  });

  it('turns a rejected fetch into network and an aborted one into timeout', async () => {
    const a = makeCtx({
      source,
      routes: [
        route(URL1, () => {
          throw new TypeError('connection reset');
        }),
      ],
    });
    expect(await failure(request(a.ctx, URL1))).toMatchObject({ code: 'network', retryable: true });
    const b = makeCtx({
      source,
      routes: [
        route(
          URL1,
          (_r, signal) =>
            new Promise<Response>((_res, rej) => {
              signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')));
            }),
        ),
      ],
    });
    expect(await failure(request(b.ctx, URL1, { timeoutMs: 20 }))).toMatchObject({
      code: 'timeout',
      retryable: true,
    });
  });

  it('reports an abort from the caller signal as cancelled, not timeout', async () => {
    const ac = new AbortController();
    const h = makeCtx({
      source,
      routes: [
        route(
          URL1,
          (_r, signal) =>
            new Promise<Response>((_res, rej) => {
              signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')));
              ac.abort();
            }),
        ),
      ],
    });
    h.ctx.signal = ac.signal;
    expect(await failure(request(h.ctx, URL1))).toMatchObject({ code: 'cancelled', retryable: true });
  });

  it('rejects a body over maxBytes, by Content-Length and while streaming', async () => {
    const a = makeCtx({
      source,
      routes: [route(URL1, reply('x'.repeat(10), 200, { 'content-length': '10' }))],
    });
    expect(await failure(request(a.ctx, URL1, { maxBytes: 5 }))).toMatchObject({
      code: 'too-large',
      retryable: false,
    });
    const stream = () =>
      new Response(
        new ReadableStream({
          start(c) {
            c.enqueue(new TextEncoder().encode('xxx'));
            c.enqueue(new TextEncoder().encode('xxx'));
            c.close();
          },
        }),
      );
    const b = makeCtx({ source, routes: [route(URL1, stream)] });
    expect((await failure(request(b.ctx, URL1, { maxBytes: 5 }))).code).toBe('too-large');
    expect((await request(b.ctx, URL1, { maxBytes: 6 })).text).toBe('xxxxxx');
  });

  it('allows 60 requests per context and refuses the 61st', async () => {
    const h = makeCtx({ source, routes: [route(URL1, reply('ok'))] });
    for (let i = 0; i < MAX_REQUESTS_PER_STEP; i++) await request(h.ctx, URL1);
    expect((await failure(request(h.ctx, URL1))).code).toBe('request-budget');
    expect(h.requests).toHaveLength(MAX_REQUESTS_PER_STEP);
    // a new context starts again
    const fresh = makeCtx({ source, routes: [route(URL1, reply('ok'))] });
    await request(fresh.ctx, URL1);
  });

  it('with rateLimit.perMinute runs one at a time, 60000/perMinute apart', async () => {
    const h = makeCtx({
      source: { ...source, rateLimit: { perMinute: 6 } },
      routes: [route(URL1, reply('ok'))],
    });
    await Promise.all([request(h.ctx, URL1), request(h.ctx, URL1), request(h.ctx, URL1)]);
    expect(h.waits).toEqual([10_000, 10_000]);
  });

  it('without a pause, runs at most 6 at once', async () => {
    let active = 0;
    let peak = 0;
    const h = makeCtx({
      source,
      routes: [
        route(URL1, async () => {
          active++;
          peak = Math.max(peak, active);
          await new Promise((r) => setTimeout(r, 5));
          active--;
          return new Response('ok');
        }),
      ],
    });
    await Promise.all(Array.from({ length: 20 }, () => request(h.ctx, URL1)));
    expect(peak).toBe(6);
  });

  describe('credentials', () => {
    const auth = { credential: 'nvd' as const, header: 'apiKey' };
    const SECRET = 'sekrit-key-123';

    it('sends the credential only to the origin of the URL', async () => {
      const h = makeCtx({ source, credentials: { nvd: SECRET }, routes: [route(URL1, reply('ok'))] });
      await request(h.ctx, URL1, { auth });
      expect(h.requests[0]?.headers.apikey).toBe(SECRET);
      const bearer = makeCtx({ source, credentials: { github: SECRET }, routes: [route(URL1, reply('ok'))] });
      await request(bearer.ctx, URL1, {
        auth: { credential: 'github', header: 'authorization', scheme: 'Bearer' },
      });
      expect(bearer.requests[0]?.headers.authorization).toBe(`Bearer ${SECRET}`);
      const none = makeCtx({ source, routes: [route(URL1, reply('ok'))] });
      await request(none.ctx, URL1, { auth });
      expect(none.requests[0]?.headers.apikey).toBeUndefined();
    });

    it('follows same-origin redirects with it and drops it on a cross-origin one', async () => {
      const h = makeCtx({
        source,
        credentials: { nvd: SECRET },
        routes: [
          route(URL1, reply('', 302, { location: '/moved' })),
          route('https://example.test/moved', reply('', 302, { location: 'https://other.test/final' })),
          route('https://other.test/final', reply('done')),
        ],
      });
      const r = await request(h.ctx, URL1, { auth });
      expect(r.text).toBe('done');
      expect(h.requests.map((q) => q.headers.apikey)).toEqual([SECRET, SECRET, undefined]);
      expect(h.requests.every((q) => q.url !== undefined)).toBe(true);
    });

    it('stops after 3 redirects', async () => {
      const h = makeCtx({ source, routes: [route(/example\.test/, reply('', 302, { location: '/again' }))] });
      expect((await failure(request(h.ctx, URL1))).code).toBe('http');
      expect(h.requests).toHaveLength(4);
    });

    it('never puts the credential in a log, an error or a message', async () => {
      const ok = makeCtx({
        source,
        credentials: { nvd: SECRET },
        routes: [route(`${URL1}?q=1`, reply('body-text'))],
      });
      await request(ok.ctx, `${URL1}?q=1`, { auth });
      expect(JSON.stringify(ok.logs)).not.toContain(SECRET);
      expect(JSON.stringify(ok.logs)).not.toContain('q=1');
      expect(ok.logs[0]).toMatchObject({
        msg: 'http',
        extra: { origin: 'https://example.test', path: '/data', status: 200, bytes: 9 },
      });
      const bad = makeCtx({
        source,
        credentials: { nvd: SECRET },
        routes: [route(URL1, reply(`echo ${SECRET}`, 500))],
      });
      const e = await failure(request(bad.ctx, URL1, { auth }));
      expect(`${e.message} ${JSON.stringify(e)} ${String(e.cause)}`).not.toContain(SECRET);
      expect(JSON.stringify(bad.logs)).not.toContain(SECRET);
    });
  });
});
