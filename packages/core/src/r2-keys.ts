import { normaliseId } from './ids';

/** R2 key builders. Pure and synchronous, so Workers and E2B jobs agree on every key. */

const pad = (n: number, width = 2) => String(n).padStart(width, '0');

/** raw/<source>/<yyyy>/<mm>/<dd>/<runId>-<step>.ndjson.gz (UTC date) */
export function rawReceiptKey(sourceId: string, runId: string, step: number, at: Date): string {
  const y = pad(at.getUTCFullYear(), 4);
  const m = pad(at.getUTCMonth() + 1);
  const d = pad(at.getUTCDate());
  return `raw/${sourceId}/${y}/${m}/${d}/${runId}-${step}.ndjson.gz`;
}

/** jobs/<jobId>/ */
export function jobPrefix(jobId: string): string {
  return `jobs/${jobId}/`;
}

/** docs/vuln/<key>.json */
export function vulnDocKey(vulnKey: string): string {
  return `docs/vuln/${vulnKey}.json`;
}

export const VULN_SHARDS = 4096;

/**
 * Three lowercase hex digits (000–fff): FNV-1a 32-bit of the normalised key, modulo 4,096.
 * The key is normalised with `normaliseId` first, so `cve-2024-1` and `CVE-2024-1` share a shard.
 */
export function vulnShard(vulnKey: string): string {
  const bytes = new TextEncoder().encode(normaliseId(vulnKey));
  let h = 0x811c9dc5;
  for (const b of bytes) {
    h ^= b;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return (h % VULN_SHARDS).toString(16).padStart(3, '0');
}

/**
 * lookup/vuln/<shard>.json: a JSON object keyed by normalised vulnerability key; each value is a row
 * shaped like a `vulns` row.
 */
export function lookupVulnKey(vulnKey: string): string {
  return `lookup/vuln/${vulnShard(vulnKey)}.json`;
}

/** lookup/index/<letter>.json, an `IndexLetterResponse`. Letter is `a`–`z`, or `0` for digits. */
export function indexLetterKey(letter: string): string {
  return `lookup/index/${letter}.json`;
}

/** lake/<table>/<source>/<year>/part-<part>.parquet */
export function lakeKey(table: string, sourceId: string, year: number, part: number): string {
  return `lake/${table}/${sourceId}/${year}/part-${part}.parquet`;
}

/** sitemap.xml */
export function sitemapKey(): string {
  return 'sitemap.xml';
}
