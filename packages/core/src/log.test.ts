import { afterEach, describe, expect, it, vi } from 'vitest';
import { logEvent, requestIdFrom, safeFields } from './log';

describe('requestIdFrom', () => {
  it('keeps a well-formed id', () => {
    expect(requestIdFrom('abcd1234-ef')).toBe('abcd1234-ef');
  });
  it('replaces missing, short, long and odd ids', () => {
    for (const bad of [
      null,
      '',
      'short',
      'x'.repeat(65),
      'has space 1234',
      'a\nb-12345678',
      'ünï-12345678',
    ]) {
      const id = requestIdFrom(bad);
      expect(id).not.toBe(bad);
      expect(id).toMatch(/^[0-9a-f-]{36}$/);
    }
  });
});

describe('safeFields', () => {
  it('keeps primitives and drops objects, arrays and undefined', () => {
    expect(safeFields({ a: 1, b: 'x', c: true, d: null, e: { z: 1 }, f: [1], g: undefined })).toEqual({
      a: 1,
      b: 'x',
      c: true,
      d: null,
    });
  });
  it('drops sensitive keys', () => {
    const out = safeFields({
      email: 'a',
      userEmail: 'a',
      token: 'a',
      secret: 'a',
      password: 'a',
      Authorization: 'a',
      cookie: 'a',
      signature: 'a',
      ip: 'a',
      clientIp: 'a',
      route: '/v1/search',
    });
    expect(out).toEqual({ route: '/v1/search' });
  });
  it('redacts strings holding an email and cuts long strings', () => {
    const out = safeFields({ msg: 'failed for bob@example.com today', long: 'y'.repeat(500) });
    expect(out.msg).toBe('[redacted]');
    expect((out.long as string).length).toBe(200);
  });
});

describe('logEvent', () => {
  afterEach(() => vi.restoreAllMocks());
  it('writes one JSON line', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    logEvent('info', 'request', { status: 200, email: 'x@y.zz' });
    expect(spy).toHaveBeenCalledTimes(1);
    expect(JSON.parse(spy.mock.calls[0]?.[0] as string)).toEqual({
      level: 'info',
      event: 'request',
      status: 200,
    });
  });
  it('uses console.error for errors', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    logEvent('error', 'boom');
    expect(JSON.parse(spy.mock.calls[0]?.[0] as string)).toEqual({ level: 'error', event: 'boom' });
  });
});
