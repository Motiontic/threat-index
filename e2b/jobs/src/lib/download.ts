import { createWriteStream } from 'node:fs';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { createGunzip } from 'node:zlib';

export const MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024;
export const MAX_REDIRECTS = 5;
export const USER_AGENT = 'ThreatIndex-jobs (+https://github.com/Motiontic/threat-index)';
const RETRIES = 3;

export interface DownloadDeps {
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  maxBytes?: number;
  /** Overrides the default of gunzipping when the URL path ends `.gz`; `false` keeps the bytes as served. */
  gunzip?: boolean;
}
export interface Downloaded {
  bytes: number; // written to `dest`, after gunzip
  contentType: string;
}

function assertHttps(url: string): URL {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error('download refused: not a URL');
  }
  if (u.protocol !== 'https:') throw new Error('download refused: only https: URLs are allowed');
  return u;
}

/** Counts bytes and fails the stream past `max`. */
function limit(max: number, what: string): Transform {
  let seen = 0;
  return new Transform({
    transform(chunk: Buffer, _enc, cb) {
      seen += chunk.length;
      if (seen > max) cb(new Error(`download refused: ${what} is over the size limit`));
      else cb(null, chunk);
    },
  });
}

/**
 * Fetches an `https:` URL into `dest`: follows at most 5 redirects (each `https:`), caps the size at 1 GiB,
 * retries 3 times on a network error or a 5xx, and gunzips when the URL path ends `.gz`.
 * Errors never carry the URL.
 */
export async function download(url: string, dest: string, deps: DownloadDeps = {}): Promise<Downloaded> {
  const doFetch = deps.fetch ?? fetch;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const max = deps.maxBytes ?? MAX_DOWNLOAD_BYTES;
  const gunzip = deps.gunzip ?? assertHttps(url).pathname.endsWith('.gz');
  assertHttps(url);

  let lastError = '';
  for (let attempt = 0; attempt <= RETRIES; attempt++) {
    if (attempt > 0) await sleep(500 * 2 ** (attempt - 1));
    let current = url;
    let res: Response | undefined;
    try {
      for (let hops = 0; ; hops++) {
        assertHttps(current);
        res = await doFetch(current, { redirect: 'manual', headers: { 'user-agent': USER_AGENT } });
        if (res.status >= 300 && res.status < 400 && res.headers.has('location')) {
          if (hops >= MAX_REDIRECTS) throw new Error('download refused: too many redirects');
          current = new URL(res.headers.get('location') as string, current).href;
          await res.body?.cancel();
          continue;
        }
        break;
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('download refused')) throw err;
      lastError = 'network error';
      continue;
    }
    if (res.status >= 500) {
      await res.body?.cancel();
      lastError = `status ${res.status}`;
      continue;
    }
    if (!res.ok || !res.body) throw new Error(`download refused: status ${res.status}`);
    const declared = Number(res.headers.get('content-length') ?? 0);
    if (declared > max) throw new Error('download refused: file is over the size limit');

    let written = 0;
    const counter = new Transform({
      transform(chunk: Buffer, _enc, cb) {
        written += chunk.length;
        cb(null, chunk);
      },
    });
    try {
      const parts: (NodeJS.ReadableStream | NodeJS.WritableStream)[] = [
        Readable.fromWeb(res.body as unknown as WebReadableStream),
        limit(max, 'file'),
      ];
      if (gunzip) parts.push(createGunzip(), limit(max, 'unzipped file'));
      parts.push(counter, createWriteStream(dest));
      await pipeline(parts as [NodeJS.ReadableStream, ...NodeJS.ReadWriteStream[], NodeJS.WritableStream]);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('download refused')) throw err;
      lastError = 'stream error';
      continue;
    }
    return { bytes: written, contentType: res.headers.get('content-type') ?? '' };
  }
  throw new Error(`download failed after retries: ${lastError}`);
}
