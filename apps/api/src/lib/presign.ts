import { jobPrefix } from '@ti/core/r2-keys';
import { AwsClient } from 'aws4fetch';
import type { ApiJobKind } from './e2b';
import type { Bindings } from './env';

export const UPLOAD_URL_TTL_SECONDS = 600;
export const MAX_UPLOAD_URLS = 50;
const MAX_KEY_LENGTH = 256;

export interface R2SigningConfig {
  accountId: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
}

const ACCOUNT_RE = /^[0-9a-f]{32}$/;
const BUCKET_RE = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

export function r2SigningConfig(env: Bindings): R2SigningConfig | null {
  const {
    R2_ACCOUNT_ID: accountId,
    R2_BUCKET_NAME: bucket,
    R2_ACCESS_KEY_ID: id,
    R2_SECRET_ACCESS_KEY: secret,
  } = env;
  if (!accountId || !ACCOUNT_RE.test(accountId)) return null;
  if (!bucket || !BUCKET_RE.test(bucket)) return null;
  if (!id || !/^\S+$/.test(id) || !secret || !/^\S+$/.test(secret)) return null;
  return { accountId, bucket, accessKeyId: id, secretAccessKey: secret };
}

/** Objects the API writes into a sandbox prefix and later trusts; the sandbox must never overwrite them. */
export const API_OWNED_NAMES: readonly string[] = ['request.json'];

/** Prefixes a sandbox may write, by kind, on top of its own `jobs/<id>/` and `inbox/<id>/`. */
export function allowedPrefixes(kind: ApiJobKind, jobId: string, sourceId: string | null = null): string[] {
  const out = [jobPrefix(jobId), `inbox/${jobId}/`];
  if ((kind === 'first-load' || kind === 'big-file') && sourceId) out.push(`lake/records/${sourceId}/`);
  else if (kind === 'affected-backfill') out.push('lake/state/affected-backfill/');
  else if (kind === 'epss-diff') out.push('lake/epss/epss/');
  else if (kind === 'nightly-fold') out.push('lake/raw/');
  else if (kind === 'search-index')
    out.push('lookup/search/', 'lookup/index/', 'lookup/vuln/', 'lookup/pkg/');
  return out;
}

/** Single objects (not prefixes) a kind may write. */
export const ALLOWED_EXACT_KEYS: Partial<Record<ApiJobKind, string[]>> = { 'search-index': ['sitemap.xml'] };

/** Prefixes a sandbox may read. */
export function readPrefixes(jobId: string): string[] {
  return ['raw/', 'lake/', 'lookup/', jobPrefix(jobId), `inbox/${jobId}/`];
}

function keyShapeError(key: string): string | null {
  if (key.length === 0) return 'empty key';
  if (key.length > MAX_KEY_LENGTH) return 'key too long';
  if (!/^[A-Za-z0-9._/-]+$/.test(key)) return 'bad character';
  if (key.startsWith('/')) return 'leading slash';
  for (const seg of key.split('/')) if (seg === '' || seg === '.' || seg === '..') return 'bad path segment';
  return null;
}

/** The reason a key may not be read, or null if it is inside `prefixes` and well formed. */
export function readKeyError(key: string, prefixes: string[]): string | null {
  const shape = keyShapeError(key);
  if (shape) return shape;
  return prefixes.some((p) => key.startsWith(p)) ? null : 'outside allowed prefixes';
}

/** The reason a list prefix is refused, or null. A prefix may end in `/` and may be a read prefix itself. */
export function listPrefixError(prefix: string, prefixes: string[]): string | null {
  if (prefix.length === 0) return 'empty prefix';
  const bare = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  const shape = keyShapeError(bare);
  if (shape) return shape;
  return prefixes.some((p) => prefix.startsWith(p)) ? null : 'outside allowed prefixes';
}

/** The reason a key is refused, or null if the key is inside `prefixes` (or is one of `exact`) and well formed. */
export function uploadKeyError(key: string, prefixes: string[], exact: string[] = []): string | null {
  const shape = keyShapeError(key);
  if (shape) return shape;
  if (exact.includes(key)) return null;
  if (prefixes.includes(key)) return 'bare prefix';
  if (!prefixes.some((p) => key.startsWith(p))) return 'outside allowed prefixes';
  for (const p of prefixes) {
    if (key.startsWith(p) && API_OWNED_NAMES.includes(key.slice(p.length))) return 'reserved key';
  }
  return null;
}

/** A presigned R2 PUT URL (a bearer token: never log it). TTL is clamped to 1–3600 s. */
export async function presignPut(
  cfg: R2SigningConfig,
  key: string,
  ttlSeconds: number = UPLOAD_URL_TTL_SECONDS,
): Promise<string> {
  const ttl = Math.min(3600, Math.max(1, Math.floor(ttlSeconds)));
  const client = new AwsClient({
    accessKeyId: cfg.accessKeyId,
    secretAccessKey: cfg.secretAccessKey,
    service: 's3',
    region: 'auto',
  });
  const path = key.split('/').map(encodeURIComponent).join('/');
  const url = new URL(`https://${cfg.accountId}.r2.cloudflarestorage.com/${cfg.bucket}/${path}`);
  url.searchParams.set('X-Amz-Expires', String(ttl));
  const signed = await client.sign(new Request(url, { method: 'PUT' }), { aws: { signQuery: true } });
  return signed.url;
}
