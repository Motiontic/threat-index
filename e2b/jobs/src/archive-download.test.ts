import { readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { run as firstLoad } from './jobs/first-load.ts';
import { fakeApi, fakeCtx, job, makeTar, noSleep } from './test-support.ts';

const URL_ = `https://github.com/CVEProject/cvelistV5/archive/${'c'.repeat(40)}.tar.gz`;
const base = { duckdb: () => null, sleep: noSleep, now: () => new Date('2026-11-24T00:00:00Z') };
const FILES = 5_100; // above the 5000-doc batch, so a batch runs while entries are still being read

const archive = (): Buffer => {
  const body = fixture('cve-list', 'rejected.json');
  const parts: Buffer[] = [];
  for (let i = 0; i < FILES; i++)
    parts.push(
      makeTar([{ path: `cvelistV5-main/cves/2024/0xxx/CVE-2024-${i}.json`, data: body }], { end: false }),
    );
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts), { level: 1 });
};

const keptOf = (logs: { msg: string; extra?: Record<string, unknown> }[]) =>
  logs.find((l) => l.msg === 'archive read')?.extra?.kept;

const scratchDirs = (id: string) => readdirSync(tmpdir()).filter((d) => d.startsWith(`job-${id}-`));

/** A fetch whose body is `bytes`, optionally cut after `cutAt` bytes with an error; records order in `events`. */
function orderedFetch(bytes: Buffer, events: string[], cutFirstAt?: number) {
  let attempt = 0;
  return (async () => {
    attempt++;
    const cut = attempt === 1 ? cutFirstAt : undefined;
    const end = cut ?? bytes.length;
    events.push('fetch-start');
    let o = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        if (o >= end) {
          if (cut !== undefined) c.error(new Error('terminated'));
          else {
            events.push('body-complete');
            c.close();
          }
          return;
        }
        c.enqueue(new Uint8Array(bytes.subarray(o, Math.min(o + 65536, end))));
        o += 65536;
      },
    });
    return new Response(body);
  }) as unknown as typeof fetch;
}

/** True when no API call (so no batch) happened after the last fetch began and before its body completed. */
const noApiBetweenFetchAndComplete = (events: string[]) =>
  !events
    .slice(events.lastIndexOf('fetch-start'), events.indexOf('body-complete'))
    .some((e) => e.startsWith('api:'));

/** Records the first API call after the body completes, and any before it. */
function spyApi(events: string[]) {
  const api = fakeApi();
  return new Proxy(api, {
    get(t, k, r) {
      const v = Reflect.get(t, k, r);
      if (typeof v !== 'function') return v;
      return (...a: unknown[]) => {
        events.push(`api:${String(k)}`);
        return v.apply(t, a);
      };
    },
  });
}

describe('first-load archive: download before read', () => {
  const bytes = archive();

  it('finishes the download before any entry is processed, and removes the file', async () => {
    const events: string[] = [];
    const { ctx, logs } = fakeCtx(spyApi(events));
    await firstLoad(job({ id: 'ARCHDLONE', sourceId: 'cve-list', url: URL_ }), ctx, {
      ...base,
      fetch: orderedFetch(bytes, events),
    });
    expect(noApiBetweenFetchAndComplete(events)).toBe(true);
    expect(events.filter((e) => e === 'body-complete')).toHaveLength(1);
    expect(events.slice(events.indexOf('body-complete')).some((e) => e.startsWith('api:'))).toBe(true);
    expect(logs.findIndex((l) => l.msg === 'archive downloaded')).toBeLessThan(
      logs.findIndex((l) => l.msg === 'archive read'),
    );
    const dl = logs.find((l) => l.msg === 'archive downloaded')?.extra as Record<string, number>;
    expect(dl.bytes).toBe(bytes.length);
    expect(JSON.stringify(logs)).not.toContain('github.com');
    expect(keptOf(logs)).toBe(FILES);
    expect(scratchDirs('ARCHDLONE')).toEqual([]);
  }, 120_000);

  it('retries a body that fails half way and completes the load', async () => {
    const events: string[] = [];
    const { ctx, logs } = fakeCtx(spyApi(events));
    await firstLoad(job({ id: 'ARCHDLTWO', sourceId: 'cve-list', url: URL_ }), ctx, {
      ...base,
      fetch: orderedFetch(bytes, events, Math.floor(bytes.length / 2)),
    });
    expect(keptOf(logs)).toBe(FILES);
    expect(noApiBetweenFetchAndComplete(events)).toBe(true);
    expect(scratchDirs('ARCHDLTWO')).toEqual([]);
  }, 120_000);

  it('removes the file when the load fails, without leaking the URL', async () => {
    const events: string[] = [];
    const bad = Buffer.concat([bytes.subarray(0, 1000), Buffer.from('not gzip')]);
    const { ctx } = fakeCtx(spyApi(events));
    const err = await firstLoad(job({ id: 'ARCHDLTHREE', sourceId: 'cve-list', url: URL_ }), ctx, {
      ...base,
      fetch: orderedFetch(bad, events),
    }).catch((e) => e as Error);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).not.toContain('github.com');
    expect(scratchDirs('ARCHDLTHREE')).toEqual([]);
  });
});
