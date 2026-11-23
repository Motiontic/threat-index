import type { Cursor } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { check, fetch, type GitFile } from '../src/git';
import { EXAMPLES, sourceWith } from './examples';
import { cursorOf, type Harness, makeCtx, NOW, reply, route, SHA_A, SHA_B } from './helpers';

const API = 'https://api.github.com/repos/CVEProject/cvelistV5';
const RAW = `https://raw.githubusercontent.com/CVEProject/cvelistV5/${SHA_B}`;
const commitsUrl = `${API}/commits/main`;
const compareRe = (head = SHA_B) =>
  new RegExp(`^${API.replace(/[./]/g, '\\$&')}/compare/${SHA_A}\\.\\.\\.${head}\\?`);
const at = (sha: string): Cursor => ({ kind: 'commit', value: sha });
const source = sourceWith('cve-list');

const record = fixture('cve-list', 'pattern-CVE-2025-3248.json');

function files(n: number, prefix = 'cves/2025/9xxx/CVE-2025-'): Array<{ filename: string; status: string }> {
  return Array.from({ length: n }, (_, i) => ({
    filename: `${prefix}${String(1000 + i)}.json`,
    status: 'added',
  }));
}
/** A compare response that pages its files 100 at a time. */
function pagedCompare(all: Array<{ filename: string; status: string }>, commits = [{ sha: SHA_B }]) {
  return (req: { url: string }) => {
    const page = Number(new URL(req.url).searchParams.get('page') ?? '1');
    return new Response(
      JSON.stringify({
        status: 'ahead',
        total_commits: commits.length,
        commits,
        files: all.slice((page - 1) * 100, page * 100),
      }),
    );
  };
}

function ids(h: Harness): string[] {
  return h.requests.map((r) => r.url);
}

describe('git', () => {
  it('check: a 304 or the same SHA is unchanged; a new SHA is changed; sends the quoted SHA', async () => {
    const a = makeCtx({ source, cursor: at(SHA_A), routes: [route(commitsUrl, reply(null, 304))] });
    expect(await check(a.ctx)).toBe('unchanged');
    expect(a.requests[0]?.headers['if-none-match']).toBe(`"${SHA_A}"`);
    expect(a.requests[0]?.headers.accept).toBe('application/vnd.github.sha');
    const b = makeCtx({ source, cursor: at(SHA_A), routes: [route(commitsUrl, reply(SHA_A))] });
    expect(await check(b.ctx)).toBe('unchanged');
    const c = makeCtx({ source, cursor: at(SHA_A), routes: [route(commitsUrl, reply(SHA_B))] });
    expect(await check(c.ctx)).toBe('changed');
  });

  it('check: a null or mid-run cursor is changed without a request', async () => {
    const a = makeCtx({ source });
    expect(await check(a.ctx)).toBe('changed');
    const mid = {
      kind: 'commit' as const,
      value: JSON.stringify({ base: SHA_A, head: SHA_B, done: 3, tip: true }),
    };
    const b = makeCtx({ source, cursor: mid });
    expect(await check(b.ctx)).toBe('changed');
    expect(a.requests.length + b.requests.length).toBe(0);
  });

  it('fetch with nothing new keeps the cursor', async () => {
    const h = makeCtx({ source, cursor: at(SHA_A), routes: [route(commitsUrl, reply(null, 304))] });
    const r = await fetch(h.ctx);
    expect(r).toMatchObject({ items: [], receipt: null, more: false, nextCursor: at(SHA_A) });
  });

  it('fetch: changed and added files are downloaded, removed ones are not, .py and non-included never', async () => {
    const h = makeCtx({
      source,
      cursor: at(SHA_A),
      runId: 'run-1',
      credentials: { github: 'ghp_SECRET' },
      routes: [
        route(commitsUrl, reply(SHA_B)),
        route(compareRe(), () => new Response(fixture('cve-list', 'pattern-compare.json'))),
        route(
          new RegExp(`^${RAW.replace(/[./]/g, '\\$&')}/cves/.*\\.json$`),
          reply(record, 200, { 'content-type': 'application/json' }),
        ),
      ],
    });
    const r = await fetch(h.ctx);
    expect(r.items.map((i) => i.id)).toEqual([
      'cves/2025/3xxx/CVE-2025-3248.json',
      'cves/2025/3xxx/CVE-2025-3249.json',
      'cves/2024/1xxx/CVE-2024-1000.json',
      'cves/2025/4xxx/CVE-2025-4001.json',
    ]);
    const bodies = r.items.map((i) => i.body as GitFile);
    expect(bodies.map((b) => b.status)).toEqual(['modified', 'added', 'removed', 'renamed']);
    expect(bodies[2]?.text).toBeNull();
    expect(bodies[3]?.previousPath).toBe('cves/2025/4xxx/CVE-2025-4000.json');
    expect(bodies[0]?.text).toBe(record);
    expect(ids(h).some((u) => u.endsWith('.py') || u.endsWith('README.md'))).toBe(false);
    expect(ids(h).some((u) => u.includes('CVE-2024-1000'))).toBe(false);
    expect(r).toMatchObject({ more: false, nextCursor: at(SHA_B) });
    expect(r.receipt).toMatchObject({
      source: 'cve-list',
      runId: 'run-1',
      contentType: 'application/x-ndjson',
    });
    const lines = String(r.receipt?.body)
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l));
    expect(lines.length).toBe(4); // compare (for the removed file) + 3 downloads
    expect(lines.every((l) => l.url && l.status && !('headers' in l))).toBe(true);
    // The token goes to api.github.com only.
    for (const q of h.requests)
      expect(q.headers.authorization).toBe(
        new URL(q.url).host === 'api.github.com' ? 'Bearer ghp_SECRET' : undefined,
      );
    expect(JSON.stringify(h.logs)).not.toContain('ghp_SECRET');
    expect(JSON.stringify(r)).not.toContain('ghp_SECRET');
  });

  it('fetch: over 40 files gives 40 and more, then the rest', async () => {
    const all = files(45);
    const routes = [
      route(commitsUrl, reply(SHA_B)),
      route(compareRe(), pagedCompare(all)),
      route(/raw\.githubusercontent\.com/, reply(record)),
    ];
    const first = makeCtx({ source, cursor: at(SHA_A), routes });
    const r1 = await fetch(first.ctx);
    expect(r1.items).toHaveLength(40);
    expect(r1.more).toBe(true);
    expect(JSON.parse(cursorOf(r1).value)).toEqual({ base: SHA_A, head: SHA_B, done: 40, tip: true });
    expect(r1.nextCursor?.etag).toBeUndefined();

    const second = makeCtx({ source, cursor: r1.nextCursor, routes });
    expect(await check(second.ctx)).toBe('changed');
    const r2 = await fetch(second.ctx);
    expect(r2.items).toHaveLength(5);
    expect(r2.items[0]?.id).toBe(all[40]?.filename);
    expect(r2).toMatchObject({ more: false, nextCursor: at(SHA_B) });
    // a mid-run cursor does not look the head up again
    expect(ids(second).some((u) => u.includes('/commits/'))).toBe(false);
  });

  it('fetch: a null cursor hands off a first load and starts no downloads', async () => {
    const h = makeCtx({ source, routes: [route(commitsUrl, reply(SHA_B))] });
    const r = await fetch(h.ctx);
    expect(r).toMatchObject({ items: [], receipt: null, more: false, nextCursor: at(SHA_B) });
    expect(r.heavy).toEqual({
      kind: 'first-load',
      sourceId: 'cve-list',
      url: `https://github.com/CVEProject/cvelistV5/archive/${SHA_B}.tar.gz`,
      reason: `none → ${SHA_B}`,
    });
    expect(h.requests).toHaveLength(1);
  });

  it('fetch: diverged, and a base that is gone, are first loads', async () => {
    const diverged = makeCtx({
      source,
      cursor: at(SHA_A),
      routes: [
        route(commitsUrl, reply(SHA_B)),
        route(compareRe(), reply(JSON.stringify({ status: 'diverged', files: [] }))),
      ],
    });
    expect((await fetch(diverged.ctx)).heavy?.kind).toBe('first-load');
    const gone = makeCtx({
      source,
      cursor: at(SHA_A),
      routes: [route(commitsUrl, reply(SHA_B)), route(compareRe(), reply('{}', 404))],
    });
    const r = await fetch(gone.ctx);
    expect(r.heavy?.kind).toBe('first-load');
    expect(r.nextCursor).toEqual(at(SHA_B));
  });

  it('fetch: at the 300-file cap, narrows head to the first commit after base', async () => {
    const first = 'c'.repeat(40);
    const commits = [{ sha: first }, { sha: SHA_B }];
    const routes = [
      route(commitsUrl, reply(SHA_B)),
      route(compareRe(), pagedCompare(files(300), commits)),
      route(compareRe(first), pagedCompare(files(3), [{ sha: first }])),
      route(/raw\.githubusercontent\.com/, reply(record)),
    ];
    const h = makeCtx({ source, cursor: at(SHA_A), routes });
    const r = await fetch(h.ctx);
    expect(r.items).toHaveLength(3);
    expect(r.more).toBe(true);
    expect(JSON.parse(cursorOf(r).value)).toEqual({ base: first, head: first, done: 0, tip: false });
    expect(
      ids(h)
        .filter((u) => u.startsWith('https://raw.'))
        .every((u) => u.includes(`/${first}/`)),
    ).toBe(true);
    // The next step resumes from the narrowed head toward the branch head.
    const next = makeCtx({
      source,
      cursor: r.nextCursor,
      routes: [
        route(commitsUrl, reply(SHA_B)),
        route(new RegExp(`compare/${first}\\.\\.\\.${SHA_B}\\?`), pagedCompare(files(2), [{ sha: SHA_B }])),
        route(/raw\.githubusercontent\.com/, reply(record)),
      ],
    });
    const r2 = await fetch(next.ctx);
    expect(r2).toMatchObject({ more: false, nextCursor: at(SHA_B) });
    expect(r2.items).toHaveLength(2);
  });

  it('fetch: still capped after narrowing is a big-file hand-off', async () => {
    const first = 'c'.repeat(40);
    const h = makeCtx({
      source,
      cursor: at(SHA_A),
      routes: [
        route(commitsUrl, reply(SHA_B)),
        route(compareRe(), pagedCompare(files(300), [{ sha: first }, { sha: SHA_B }])),
        route(compareRe(first), pagedCompare(files(300), [{ sha: first }])),
      ],
    });
    const r = await fetch(h.ctx);
    expect(r.items).toEqual([]);
    expect(r.heavy?.kind).toBe('big-file');
    expect(r.nextCursor).toEqual(at(first));
  });

  it('fetch: a file over the size limit is handed off after the items before it', async () => {
    const all = [...files(2), ...files(1, 'cves/2025/8xxx/CVE-2025-')];
    const big = all[1]?.filename ?? '';
    const routes = [
      route(commitsUrl, reply(SHA_B)),
      route(compareRe(), pagedCompare(all)),
      route(
        new RegExp(`${big.replace(/[./]/g, '\\$&')}$`),
        reply('x'.repeat(20), 200, { 'content-length': String(6 * 1024 * 1024) }),
      ),
      route(/raw\.githubusercontent\.com/, reply(record)),
    ];
    const r1 = await fetch(makeCtx({ source, cursor: at(SHA_A), routes }).ctx);
    expect(r1.items).toHaveLength(1);
    expect(r1.more).toBe(true);
    const r2 = await fetch(makeCtx({ source, cursor: r1.nextCursor, routes }).ctx);
    expect(r2.items).toEqual([]);
    expect(r2.heavy).toMatchObject({ kind: 'big-file', sourceId: 'cve-list' });
    expect(r2.heavy?.url).toContain(big);
    expect(JSON.parse(cursorOf(r2).value)).toMatchObject({ done: 2 });
  });

  it('fetch: a source with heavy hands off on a change, with the job kind, and downloads nothing', async () => {
    const heavy = { ...source, heavy: true, pull: { ...EXAMPLES['cve-list'], jobKind: 'big-file' as const } };
    const h = makeCtx({ source: heavy, cursor: at(SHA_A), routes: [route(commitsUrl, reply(SHA_B))] });
    const r = await fetch(h.ctx);
    expect(r.heavy?.kind).toBe('big-file');
    expect(h.requests).toHaveLength(1);
  });

  it('logs once when there is no GitHub token', async () => {
    const h = makeCtx({ source, cursor: at(SHA_A), routes: [route(commitsUrl, reply(SHA_A))] });
    await check(h.ctx);
    await check(h.ctx);
    expect(h.logs.filter((l) => l.msg.includes('no github credential'))).toHaveLength(1);
    expect(h.requests[0]?.headers.authorization).toBeUndefined();
  });

  it('time comes from ctx.now (receipt fetchedAt)', async () => {
    const h = makeCtx({
      source,
      cursor: at(SHA_A),
      routes: [
        route(commitsUrl, reply(SHA_B)),
        route(compareRe(), pagedCompare(files(1))),
        route(/raw\.githubusercontent\.com/, reply(record)),
      ],
    });
    expect((await fetch(h.ctx)).receipt?.fetchedAt).toBe(NOW.toISOString());
  });
});
