import { deriveJobKey, SIGNATURE_HEADER, TIMESTAMP_HEADER, verifyRequest } from '@ti/core/sign';
import { describe, expect, it } from 'vitest';
import { createJobApi, MAX_OBJECT_BYTES, sha256Hex } from './client.ts';
import { JOB_ID, noSleep } from './test-support.ts';

const SECRET = 'ops-secret';
const BASE = 'https://api.test';

interface Seen {
  method: string;
  url: URL;
  headers: Headers;
  body: Uint8Array;
}

async function setup(handler: (seen: Seen, n: number) => Response | Promise<Response>) {
  const seen: Seen[] = [];
  const key = await deriveJobKey(SECRET, JOB_ID);
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as string, init);
    const s = {
      method: req.method,
      url: new URL(req.url),
      headers: req.headers,
      body: new Uint8Array(await req.arrayBuffer()),
    };
    seen.push(s);
    return handler(s, seen.length);
  }) as typeof fetch;
  const api = createJobApi(
    { id: JOB_ID, apiBase: BASE, hmac: key },
    { fetch: fetchFn, sleep: noSleep, now: () => Date.now() },
  );
  return { api, seen, key };
}

/** Verifies like the API does: the signed path is pathname + search, the signed body is `signedBody`. */
const verifies = (key: string, s: Seen, signedBody: string) =>
  verifyRequest(key, {
    method: s.method,
    path: s.url.pathname + s.url.search,
    timestamp: s.headers.get(TIMESTAMP_HEADER),
    signature: s.headers.get(SIGNATURE_HEADER),
    body: signedBody,
  });

describe('putObject', () => {
  it('signs the digest, sends it as a header, and sends the bytes', async () => {
    const { api, seen, key } = await setup(() => Response.json({ key: 'k', size: 3 }));
    await api.putObject(`jobs/${JOB_ID}/a.json`, 'abc', 'application/json');
    const s = seen[0] as Seen;
    const digest = await sha256Hex(new TextEncoder().encode('abc'));
    expect(s.method).toBe('PUT');
    expect(s.url.pathname).toBe(`/internal/jobs/${JOB_ID}/objects/jobs/${JOB_ID}/a.json`);
    expect(s.headers.get('x-ti-content-sha256')).toBe(digest);
    expect(s.headers.get('content-type')).toBe('application/json');
    expect(new TextDecoder().decode(s.body)).toBe('abc');
    expect(await verifies(key, s, digest)).toBe(true);
    expect(await verifies(key, s, 'abc')).toBe(false);
  });
  it('refuses a body over MAX_OBJECT_BYTES before sending', async () => {
    const { api, seen } = await setup(() => Response.json({}));
    await expect(api.putObject('k', new Uint8Array(MAX_OBJECT_BYTES + 1), 'a/b')).rejects.toThrow(
      /size limit/,
    );
    expect(seen).toHaveLength(0);
  });
  it('retries a 503 and a network error, then reports a refusal without the key', async () => {
    let n = 0;
    const { api, seen } = await setup(() => {
      n++;
      if (n === 1) return new Response(null, { status: 503 });
      if (n === 2) throw new TypeError('socket hang up');
      return Response.json({});
    });
    await api.putObject(`jobs/${JOB_ID}/x`, 'x', 'text/plain');
    expect(seen).toHaveLength(3);
    const refused = await setup(() => new Response(null, { status: 400 }));
    const err = await refused.api
      .putObject(`jobs/${JOB_ID}/secret-name`, 'x', 'text/plain')
      .catch((e) => e as Error);
    expect((err as Error).message).toBe('put-object refused: status 400');
    expect((err as Error).message).not.toContain('secret-name');
  });
});

describe('getObject', () => {
  it('signs an empty body, returns the bytes, and maps 404 to null', async () => {
    const { api, seen, key } = await setup((s) =>
      s.url.pathname.endsWith('/missing') ? new Response(null, { status: 404 }) : new Response('hello'),
    );
    expect(new TextDecoder().decode((await api.getObject('raw/a/b')) as Uint8Array)).toBe('hello');
    expect(await verifies(key, seen[0] as Seen, '')).toBe(true);
    expect(await api.getObject('raw/a/missing')).toBeNull();
  });
});

describe('list', () => {
  it('pages with a cursor and signs pathname + search', async () => {
    const { api, seen, key } = await setup((s) =>
      Response.json(
        s.url.searchParams.get('cursor') === 'c1'
          ? { objects: [{ key: 'raw/b', size: 2 }], cursor: null }
          : { objects: [{ key: 'raw/a', size: 1 }], cursor: 'c1' },
      ),
    );
    const out: { key: string; size: number }[] = [];
    for await (const o of api.list('raw/x/')) out.push(o);
    expect(out.map((o) => o.key)).toEqual(['raw/a', 'raw/b']);
    expect(seen).toHaveLength(2);
    expect(seen[0]?.url.searchParams.get('prefix')).toBe('raw/x/');
    for (const s of seen) expect(await verifies(key, s, '')).toBe(true);
  });
  it('a signature does not cover a changed query', async () => {
    const { api, seen, key } = await setup(() => Response.json({ objects: [], cursor: null }));
    for await (const _ of api.list('raw/x/')) {
      /* drain */
    }
    const s = seen[0] as Seen;
    const moved = { ...s, url: new URL(s.url.href.replace('raw%2Fx%2F', 'raw%2Fy%2F')) };
    expect(await verifies(key, moved, '')).toBe(false);
  });
});

describe('rows', () => {
  it('passes after and limit, and allRows follows next in pages of 500', async () => {
    const { api, seen } = await setup((s) => {
      const after = s.url.searchParams.get('after');
      return Response.json(
        after === 'n1' ? { rows: [{ key: 'b' }], next: null } : { rows: [{ key: 'a' }], next: 'n1' },
      );
    });
    expect(await api.rows('vulns', { after: 'zz', limit: 2 })).toEqual({ rows: [{ key: 'a' }], next: 'n1' });
    expect(seen[0]?.url.search).toBe('?after=zz&limit=2');
    const keys: unknown[] = [];
    for await (const r of api.allRows('signals')) keys.push(r.key);
    expect(keys).toEqual(['a', 'b']);
    expect(seen[1]?.url.searchParams.get('limit')).toBe('500');
    expect(seen[2]?.url.searchParams.get('after')).toBe('n1');
  });
});

describe('upload', () => {
  it('uses putObject, so it needs no presigned URLs', async () => {
    const { api, seen } = await setup(() => Response.json({}));
    await api.upload([{ key: `jobs/${JOB_ID}/e.json`, body: '{}', contentType: 'application/json' }]);
    expect(seen.map((s) => s.method)).toEqual(['PUT']);
  });
});
