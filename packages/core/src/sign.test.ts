import { describe, expect, it } from 'vitest';
import { deriveJobKey, MAX_SKEW_SECONDS, signRequest, verifyRequest } from './sign';

const NOW = new Date('2026-06-01T12:00:00Z');
const ts = Math.floor(NOW.getTime() / 1000);
const KEY = 'k-test';
const base = { method: 'POST', path: '/internal/jobs', body: '{"a":1}' };

async function good() {
  return {
    ...base,
    timestamp: String(ts),
    signature: await signRequest(KEY, base.method, base.path, ts, base.body),
  };
}

describe('signRequest / verifyRequest', () => {
  it('accepts a good signature', async () => {
    expect(await verifyRequest(KEY, await good(), NOW)).toBe(true);
  });
  it('matches a known vector', async () => {
    const sig = await signRequest('k', 'POST', '/p', 1, '');
    // computed independently with Python hmac/hashlib
    expect(sig).toBe('178c387bd58a25135a49ba4929689709c888141149b376945641c4a2eed676d5');
    expect(sig).toBe(await signRequest('k', 'post', '/p', 1, ''));
  });
  it('rejects a changed method, path, body or timestamp', async () => {
    const g = await good();
    expect(await verifyRequest(KEY, { ...g, method: 'PUT' }, NOW)).toBe(false);
    expect(await verifyRequest(KEY, { ...g, path: '/internal/jobs/x' }, NOW)).toBe(false);
    expect(await verifyRequest(KEY, { ...g, body: '{"a":2}' }, NOW)).toBe(false);
    expect(await verifyRequest(KEY, { ...g, timestamp: String(ts + 1) }, NOW)).toBe(false);
  });
  it('rejects a wrong key', async () => {
    expect(await verifyRequest('other', await good(), NOW)).toBe(false);
  });
  it('rejects a stale or future timestamp, accepts the edge', async () => {
    const sign = async (t: number) => ({
      ...base,
      timestamp: String(t),
      signature: await signRequest(KEY, base.method, base.path, t, base.body),
    });
    expect(await verifyRequest(KEY, await sign(ts - MAX_SKEW_SECONDS - 1), NOW)).toBe(false);
    expect(await verifyRequest(KEY, await sign(ts + MAX_SKEW_SECONDS + 1), NOW)).toBe(false);
    expect(await verifyRequest(KEY, await sign(ts - MAX_SKEW_SECONDS), NOW)).toBe(true);
  });
  it('fails closed on a missing key', async () => {
    expect(await verifyRequest(undefined, await good(), NOW)).toBe(false);
    expect(await verifyRequest('', await good(), NOW)).toBe(false);
  });
  it('rejects a missing header or malformed timestamp', async () => {
    const g = await good();
    expect(await verifyRequest(KEY, { ...g, signature: null }, NOW)).toBe(false);
    expect(await verifyRequest(KEY, { ...g, timestamp: null }, NOW)).toBe(false);
    expect(await verifyRequest(KEY, { ...g, timestamp: 'abc' }, NOW)).toBe(false);
    expect(await verifyRequest(KEY, { ...g, signature: 'short' }, NOW)).toBe(false);
  });
});

describe('deriveJobKey', () => {
  it('is deterministic and per job', async () => {
    const a = await deriveJobKey('s', 'job1');
    expect(a).toBe('544b5590c74560afb0bf9fa7af98a65f7ca78fd6e8970a8fe50c572412270f17');
    expect(a).toBe(await deriveJobKey('s', 'job1'));
    expect(a).not.toBe(await deriveJobKey('s', 'job2'));
    expect(a).not.toBe(await deriveJobKey('t', 'job1'));
  });
  it('throws on an empty secret', async () => {
    await expect(deriveJobKey('', 'job1')).rejects.toThrow();
  });
});
