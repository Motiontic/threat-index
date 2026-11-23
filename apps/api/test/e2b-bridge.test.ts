import { inboxChunkKey } from '@ti/core/inbox';
import { describe, expect, it } from 'vitest';
import { launcherFromEnv, newJobId, parseApiBase, parseManifest } from '../src/lib/e2b';
import type { Bindings } from '../src/lib/env';
import { allowedPrefixes, presignPut, r2SigningConfig, uploadKeyError } from '../src/lib/presign';

const ID = '01HZX3K9ABCDEFGHJKMNPQRSTV';
const env = (o: Partial<Record<string, string>>) => o as unknown as Bindings;

describe('newJobId', () => {
  it('is a 26-character Crockford ULID that sorts by time', () => {
    const a = newJobId(new Date('2026-01-01T00:00:00Z'));
    const b = newJobId(new Date('2026-01-01T00:00:01Z'));
    expect(a).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(a < b).toBe(true);
    expect(newJobId()).not.toBe(newJobId());
  });
});

describe('uploadKeyError', () => {
  const p = allowedPrefixes('echo', ID);
  it('allows keys under the job prefixes', () => {
    expect(uploadKeyError(`jobs/${ID}/echo.json`, p)).toBeNull();
    expect(uploadKeyError(`inbox/${ID}/0.ndjson.gz`, p)).toBeNull();
  });
  it.each([
    ['', 'empty'],
    ['a'.repeat(257), 'long'],
    [`jobs/${ID}/a b`, 'space'],
    [`jobs/${ID}/é`, 'non-ascii'],
    [`/jobs/${ID}/x`, 'leading slash'],
    [`jobs/${ID}//x`, 'empty segment'],
    [`jobs/${ID}/./x`, 'dot'],
    [`jobs/${ID}/../x`, 'dotdot'],
    [`jobs/${ID}/`, 'bare prefix'],
    [`inbox/${ID}/`, 'bare inbox prefix'],
    ['inbox/01HZX3K9ABCDEFGHJKMNPQRSTW/x', 'other id'],
    ['raw/x', 'raw'],
    [`jobs/${ID}x/y`, 'prefix lookalike'],
  ])('rejects %s (%s)', (key) => {
    expect(uploadKeyError(key, p)).not.toBeNull();
  });
});

describe('parseManifest', () => {
  const good = (chunks: unknown[]) =>
    JSON.stringify({ jobId: ID, createdAt: '2026-01-01T00:00:00Z', chunks });
  const c = (n: number, rows = 5) => ({ key: inboxChunkKey(ID, n), rows });
  it('accepts an empty and a normal manifest', () => {
    expect(parseManifest(good([]), ID, 'echo')).toHaveProperty('manifest');
    const r = parseManifest(good([c(0), c(1, 500)]), ID, 'first-load');
    expect('manifest' in r && r.manifest.chunks).toHaveLength(2);
  });
  it('strips fields it does not know, such as a priority', () => {
    const r = parseManifest(good([{ ...c(0), priority: 'steady' }]), ID, 'echo');
    expect('manifest' in r && r.manifest.chunks[0]).toEqual(c(0));
  });
  it.each([
    ['bad JSON', '{'],
    ['not an object', '[]'],
    ['other jobId', JSON.stringify({ jobId: 'x', createdAt: 'z', chunks: [] })],
    ['over 1 MiB', ' '.repeat(1024 * 1024 + 1)],
    ['over 5000 chunks', good(Array.from({ length: 5001 }, (_, n) => c(n)))],
    ['wrong key', good([{ key: `inbox/${ID}/9.ndjson.gz`, rows: 1 }])],
    ['repeated key', good([c(0), c(0)])],
    ['zero rows', good([c(0, 0)])],
    ['too many rows', good([c(0, 501)])],
    ['fractional rows', good([c(0, 1.5)])],
  ])('rejects %s', (_n, text) => {
    expect(parseManifest(text, ID, 'echo')).toHaveProperty('error');
  });
});

describe('launcherFromEnv', () => {
  const ok = { E2B_API_KEY: 'k', E2B_TEMPLATE: 'tmpl-1', API_BASE: 'https://api.example.com' };
  it('builds with a complete, valid environment', () => {
    expect(launcherFromEnv(env(ok))).not.toBeNull();
    expect(launcherFromEnv(env({ ...ok, API_BASE: 'http://localhost:8700' }))).not.toBeNull();
  });
  it.each([
    [{ E2B_API_KEY: '' }],
    [{ E2B_API_KEY: undefined }],
    [{ E2B_TEMPLATE: '' }],
    [{ E2B_TEMPLATE: 'bad name!' }],
    [{ API_BASE: '' }],
    [{ API_BASE: 'http://api.example.com' }],
    [{ API_BASE: 'https://api.example.com/v1' }],
    [{ API_BASE: 'https://u:p@api.example.com' }],
    [{ API_BASE: 'not a url' }],
  ])('is null for %o', (o) => {
    expect(launcherFromEnv(env({ ...ok, ...o } as Record<string, string>))).toBeNull();
  });
  it('normalises API_BASE to an origin', () => {
    expect(parseApiBase('https://api.example.com/')).toBe('https://api.example.com');
  });
});

describe('presign', () => {
  const full = {
    R2_ACCOUNT_ID: '0123456789abcdef0123456789abcdef',
    R2_BUCKET_NAME: 'threat-index-staging',
    R2_ACCESS_KEY_ID: 'AKIDEXAMPLE',
    R2_SECRET_ACCESS_KEY: 'super-secret-value',
  };
  it('r2SigningConfig is null for any missing or malformed value', () => {
    expect(r2SigningConfig(env(full))).not.toBeNull();
    for (const bad of [
      { R2_ACCOUNT_ID: undefined },
      { R2_ACCOUNT_ID: 'ABCDEF0123456789abcdef0123456789' },
      { R2_ACCOUNT_ID: 'short' },
      { R2_BUCKET_NAME: undefined },
      { R2_BUCKET_NAME: 'Bad_Bucket' },
      { R2_BUCKET_NAME: '-x-' },
      { R2_ACCESS_KEY_ID: '' },
      { R2_SECRET_ACCESS_KEY: undefined },
    ])
      expect(r2SigningConfig(env({ ...full, ...bad } as Record<string, string>))).toBeNull();
  });
  it('presigns a PUT with host, path, expiry and signature, and no secret', async () => {
    const cfg = r2SigningConfig(env(full));
    if (!cfg) throw new Error('config');
    const url = new URL(await presignPut(cfg, `jobs/${ID}/echo.json`, 600));
    expect(url.host).toBe(`${full.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`);
    expect(url.pathname).toBe(`/${full.R2_BUCKET_NAME}/jobs/${ID}/echo.json`);
    expect(url.searchParams.get('X-Amz-Expires')).toBe('600');
    expect(url.searchParams.get('X-Amz-Signature')).toMatch(/^[0-9a-f]{64}$/);
    expect(url.href).not.toContain(full.R2_SECRET_ACCESS_KEY);
  });
  it('clamps the TTL to 1–3600 seconds', async () => {
    const cfg = r2SigningConfig(env(full));
    if (!cfg) throw new Error('config');
    const ttl = async (n: number) =>
      new URL(await presignPut(cfg, `jobs/${ID}/a`, n)).searchParams.get('X-Amz-Expires');
    expect(await ttl(0)).toBe('1');
    expect(await ttl(99999)).toBe('3600');
  });
});
