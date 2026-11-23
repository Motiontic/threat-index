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
  const { R2_ACCOUNT_ID: accountId, R2_BUCKET_NAME: bucket, R2_ACCESS_KEY_ID: id, R2_SECRET_ACCESS_KEY: secret } = env;
  if (!accountId || !ACCOUNT_RE.test(accountId)) return null;
  if (!bucket || !BUCKET_RE.test(bucket)) return null;
  if (!id || !/^\S+$/.test(id) || !secret || !/^\S+$/.test(secret)) return null;
  return { accountId, bucket, accessKeyId: id, secretAccessKey: secret };
}

/** Prefixes a sandbox may write. Jobs that later write `lake/` or `lookup/` add theirs here. */
export function allowedPrefixes(_kind: ApiJobKind, jobId: string): string[] {
  return [jobPrefix(jobId), `inbox/${jobId}/`];
}

/** The reason a key is refused, or null if the key is inside `prefixes` and well formed. */
export function uploadKeyError(key: string, prefixes: string[]): string | null {
  if (key.length === 0) return 'empty key';
  if (key.length > MAX_KEY_LENGTH) return 'key too long';
  if (!/^[A-Za-z0-9._/-]+$/.test(key)) return 'bad character';
  if (key.startsWith('/')) return 'leading slash';
  for (const seg of key.split('/')) if (seg === '' || seg === '.' || seg === '..') return 'bad path segment';
  if (prefixes.includes(key)) return 'bare prefix';
  if (!prefixes.some((p) => key.startsWith(p))) return 'outside allowed prefixes';
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
