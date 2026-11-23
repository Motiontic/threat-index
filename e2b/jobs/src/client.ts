/** The sandbox's side of the API: signed calls to `upload-urls` and `complete`, and PUTs to presigned R2 URLs. */
import { signRequest, SIGNATURE_HEADER, TIMESTAMP_HEADER } from '@ti/core/sign';

export const MAX_URLS_PER_CALL = 50;
const RETRIES = 3;

export interface UploadFile {
  key: string;
  body: string | Uint8Array;
  contentType: string;
}
export type CompleteResult = { ok: true } | { ok: false; error: string };
export interface JobApi {
  uploadUrls(keys: string[]): Promise<{ key: string; url: string }[]>;
  upload(files: UploadFile[]): Promise<void>;
  complete(result: CompleteResult): Promise<void>;
}
export interface ClientDeps {
  fetch?: typeof fetch;
  now?: () => number; // ms
  sleep?: (ms: number) => Promise<void>;
}
interface JobAuth {
  id: string;
  apiBase: string;
  hmac: string;
}

export function createJobApi(job: JobAuth, deps: ClientDeps = {}): JobApi {
  const doFetch = deps.fetch ?? fetch;
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));

  async function call(route: 'upload-urls' | 'complete', payload: unknown): Promise<unknown> {
    const path = `/internal/jobs/${job.id}/${route}`;
    const body = JSON.stringify(payload);
    let lastError = '';
    for (let attempt = 0; attempt <= RETRIES; attempt++) {
      if (attempt > 0) await sleep(500 * 2 ** (attempt - 1));
      const ts = Math.floor(now() / 1000);
      let res: Response;
      try {
        res = await doFetch(`${job.apiBase}${path}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            [TIMESTAMP_HEADER]: String(ts),
            [SIGNATURE_HEADER]: await signRequest(job.hmac, 'POST', path, ts, body),
          },
          body,
        });
      } catch {
        lastError = 'network error';
        continue;
      }
      if (res.ok) return res.json();
      if (res.status >= 500) {
        lastError = `status ${res.status}`;
        continue;
      }
      throw new Error(`${route} refused: status ${res.status}`);
    }
    throw new Error(`${route} failed after retries: ${lastError}`);
  }

  async function uploadUrls(keys: string[]) {
    const out: { key: string; url: string }[] = [];
    for (let i = 0; i < keys.length; i += MAX_URLS_PER_CALL) {
      const slice = keys.slice(i, i + MAX_URLS_PER_CALL);
      const res = (await call('upload-urls', { keys: slice })) as { urls?: { key: string; url: string }[] };
      for (const key of slice) {
        const hit = res.urls?.find((u) => u.key === key);
        if (!hit) throw new Error('upload-urls reply is missing a key');
        out.push(hit);
      }
    }
    return out;
  }

  return {
    uploadUrls,
    async upload(files) {
      const urls = await uploadUrls(files.map((f) => f.key));
      for (let i = 0; i < files.length; i++) {
        const f = files[i] as UploadFile;
        const res = await doFetch((urls[i] as { url: string }).url, {
          method: 'PUT',
          headers: { 'content-type': f.contentType },
          body: f.body as BodyInit,
        });
        if (!res.ok) throw new Error(`upload of ${f.key} failed: status ${res.status}`);
      }
    },
    async complete(result) {
      await call('complete', result);
    },
  };
}
