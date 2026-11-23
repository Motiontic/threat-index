import { describe, expect, it } from 'vitest';
import {
  CLIENT_IP_HEADER,
  CLIENT_SIG_HEADER,
  CLIENT_TS_HEADER,
  ipKey,
  signClientIp,
  verifiedClientIp,
} from './edge';

const NOW = new Date('2026-11-23T12:00:00Z');
const ts = NOW.getTime() / 1000;
const RID = 'req-12345678';

async function headers(secret: string, ip: string, t = ts, rid = RID): Promise<Headers> {
  return new Headers({
    [CLIENT_IP_HEADER]: ip,
    [CLIENT_TS_HEADER]: String(t),
    [CLIENT_SIG_HEADER]: await signClientIp(secret, ip, t, rid),
    'x-request-id': rid,
  });
}

describe('verifiedClientIp', () => {
  it('round trips', async () => {
    expect(await verifiedClientIp('s', await headers('s', '203.0.113.9'), NOW)).toBe('203.0.113.9');
    expect(await verifiedClientIp('s', await headers('s', '2001:db8::1'), NOW)).toBe('2001:db8::1');
  });
  it('fails closed without a secret', async () => {
    expect(await verifiedClientIp(undefined, await headers('s', '203.0.113.9'), NOW)).toBeNull();
    expect(await verifiedClientIp('', await headers('s', '203.0.113.9'), NOW)).toBeNull();
  });
  it('rejects a wrong secret, a changed ip and a changed request id', async () => {
    expect(await verifiedClientIp('other', await headers('s', '203.0.113.9'), NOW)).toBeNull();
    const h = await headers('s', '203.0.113.9');
    h.set(CLIENT_IP_HEADER, '203.0.113.10');
    expect(await verifiedClientIp('s', h, NOW)).toBeNull();
    const h2 = await headers('s', '203.0.113.9');
    h2.set('x-request-id', 'other-request-id');
    expect(await verifiedClientIp('s', h2, NOW)).toBeNull();
  });
  it('rejects skew over 60 s, either way, and bad timestamps', async () => {
    expect(await verifiedClientIp('s', await headers('s', '203.0.113.9', ts - 61), NOW)).toBeNull();
    expect(await verifiedClientIp('s', await headers('s', '203.0.113.9', ts + 61), NOW)).toBeNull();
    expect(await verifiedClientIp('s', await headers('s', '203.0.113.9', ts - 60), NOW)).toBe('203.0.113.9');
    const h = await headers('s', '203.0.113.9');
    h.set(CLIENT_TS_HEADER, 'abc');
    expect(await verifiedClientIp('s', h, NOW)).toBeNull();
  });
  it('rejects missing headers and non-IP text even when signed', async () => {
    for (const name of [CLIENT_IP_HEADER, CLIENT_TS_HEADER, CLIENT_SIG_HEADER, 'x-request-id']) {
      const h = await headers('s', '203.0.113.9');
      h.delete(name);
      expect(await verifiedClientIp('s', h, NOW), name).toBeNull();
    }
    for (const bad of ['not an ip', '999.1.1.1', '1.2.3', '<script>', 'abc']) {
      expect(await verifiedClientIp('s', await headers('s', bad), NOW), bad).toBeNull();
    }
  });
});

describe('ipKey', () => {
  it('keeps IPv4', () => expect(ipKey('203.0.113.9')).toBe('203.0.113.9'));
  it('cuts IPv6 to a /64', () => {
    expect(ipKey('2001:db8:1:2:3:4:5:6')).toBe('2001:db8:1:2');
    expect(ipKey('2001:db8:1:2:aaaa::1')).toBe('2001:db8:1:2');
    expect(ipKey('2001:DB8::1')).toBe('2001:db8:0:0');
    expect(ipKey('::1')).toBe('0:0:0:0');
  });
  it('maps two hosts of one /64 to one key', () => {
    expect(ipKey('2001:db8:1:2::1')).toBe(ipKey('2001:db8:1:2:ffff:ffff:ffff:ffff'));
  });
});
