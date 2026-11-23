import type { Cursor } from '@ti/core/types';
import { PatternError } from './errors';
import { type HttpResult, request } from './http';
import { buildReceipt, type ReceiptPart } from './receipt';
import { MAX_ITEMS_PER_STEP, type PatternContext, type PatternResult, type RawItem } from './types';
import {
  fillTemplate,
  globToRegExp,
  heavyResult,
  jobKind,
  mapUntilTooLarge,
  parseJson,
  pullBlock,
  reasonOf,
  tryJsonObject,
  unchanged,
} from './util';

export interface GitFile {
  path: string;
  status: 'added' | 'modified' | 'removed' | 'renamed';
  previousPath?: string;
  text: string | null;
}

/** Only data files are requested. Exploit and PoC code (.py, .rb, .c ...) never is. */
const DATA_EXTENSIONS = new Set(['json', 'csv', 'md', 'xml', 'yaml', 'yml', 'txt']);
/** GitHub's compare lists at most this many files. */
const COMPARE_FILE_CAP = 300;
const COMPARE_PAGE = 100;
const API = 'https://api.github.com';
const RAW = 'https://raw.githubusercontent.com';

interface Mid {
  base: string;
  head: string;
  done: number;
  tip: boolean;
}

interface CompareFile {
  filename: string;
  status: string;
  previous_filename?: string;
}
interface Compare {
  status: string;
  total_commits?: number;
  commits?: Array<{ sha: string }>;
  files?: CompareFile[];
}

const WARNED = new WeakSet<PatternContext>();

function auth(ctx: PatternContext) {
  if (!ctx.credentials?.github && !WARNED.has(ctx)) {
    WARNED.add(ctx);
    ctx.log('no github credential: unauthenticated, 60 requests an hour per IP');
  }
  return { credential: 'github' as const, header: 'authorization', scheme: 'Bearer' };
}

function config(ctx: PatternContext) {
  const g = pullBlock(ctx, 'git');
  if (!/^[\w.-]+\/[\w.-]+$/.test(g.repo))
    throw new PatternError('pull.git.repo must be owner/name', 'not-configured');
  return { repo: g.repo, branch: g.branch ?? 'main', include: g.include.map(globToRegExp) };
}

function readMid(cursor: Cursor | null): Mid | null {
  if (!cursor) return null;
  const o = tryJsonObject(cursor.value);
  if (!o || typeof o.base !== 'string' || typeof o.head !== 'string') return null;
  return { base: o.base, head: o.head, done: Number(o.done) || 0, tip: o.tip !== false };
}

const midCursor = (m: Mid): Cursor => ({ kind: 'commit', value: JSON.stringify(m) });
const settled = (sha: string): Cursor => ({ kind: 'commit', value: sha });

async function headSha(
  ctx: PatternContext,
  repo: string,
  branch: string,
  validator?: string,
): Promise<HttpResult> {
  const url = fillTemplate(`${API}/repos/${repo}/commits/{branch}`, { branch });
  return request(ctx, url, {
    accept: 'application/vnd.github.sha',
    validator: validator ?? null,
    auth: auth(ctx),
  });
}

const archive = (repo: string, sha: string) => `https://github.com/${repo}/archive/${sha}.tar.gz`;

export async function check(ctx: PatternContext): Promise<'unchanged' | 'changed'> {
  const { repo, branch } = config(ctx);
  if (!ctx.cursor || readMid(ctx.cursor)) return 'changed';
  const sha = ctx.cursor.value;
  const res = await headSha(ctx, repo, branch, `"${sha}"`);
  if (res.notModified || res.text.trim() === sha) return 'unchanged';
  return 'changed';
}

export async function fetch(ctx: PatternContext): Promise<PatternResult> {
  const cfg = config(ctx);
  const { repo, branch } = cfg;
  const mid = readMid(ctx.cursor);

  let base: string | null;
  let head: string;
  let done = 0;
  let tip = true;
  if (mid && mid.head !== mid.base) {
    ({ base, head, done, tip } = mid);
  } else {
    base = mid ? mid.base : (ctx.cursor?.value ?? null);
    const res = await headSha(ctx, repo, branch, base ? `"${base}"` : undefined);
    if (res.notModified) return unchanged(ctx);
    head = res.text.trim();
    if (!/^[0-9a-f]{40}$/i.test(head)) throw new PatternError('unexpected commit response', 'format');
    if (head === base) return unchanged(ctx);
  }

  // No history is pulled in a Worker.
  if (base === null)
    return heavyResult(ctx, settled(head), {
      kind: 'first-load',
      url: archive(repo, head),
      reason: reasonOf(null, head),
    });

  if (ctx.source.heavy)
    return heavyResult(ctx, settled(head), {
      kind: jobKind(ctx),
      url: archive(repo, head),
      reason: reasonOf(base, head),
    });

  let cmp = await compare(ctx, repo, base, head);
  if (cmp === 'missing' || cmp.status === 'diverged')
    return heavyResult(ctx, settled(head), {
      kind: 'first-load',
      url: archive(repo, head),
      reason: reasonOf(base, head),
    });

  if ((cmp.files?.length ?? 0) >= COMPARE_FILE_CAP) {
    // Narrow to the first commit after base.
    const first = cmp.commits?.[0]?.sha;
    if (first && first !== head) {
      head = first;
      tip = false;
      done = 0;
      const narrowed = await compare(ctx, repo, base, head);
      if (narrowed === 'missing' || narrowed.status === 'diverged')
        return heavyResult(ctx, settled(head), {
          kind: 'first-load',
          url: archive(repo, head),
          reason: reasonOf(base, head),
        });
      cmp = narrowed;
    }
    if ((cmp.files?.length ?? 0) >= COMPARE_FILE_CAP)
      return heavyResult(ctx, settled(head), {
        kind: 'big-file',
        url: archive(repo, head),
        reason: `more than ${COMPARE_FILE_CAP} files changed between ${base.slice(0, 7)} and ${head.slice(0, 7)}`,
      });
  }

  const allowed = (cmp.files ?? [])
    .filter((f) => {
      const ext = f.filename.split('.').pop()?.toLowerCase() ?? '';
      return DATA_EXTENSIONS.has(ext) && cfg.include.some((re) => re.test(f.filename));
    })
    .filter((f) => f.status !== 'unchanged');
  const window = allowed.slice(done, done + MAX_ITEMS_PER_STEP);

  const parts: ReceiptPart[] = [];
  const downloaded = await mapUntilTooLarge(window, async (f) => {
    const status =
      f.status === 'removed'
        ? 'removed'
        : f.status === 'added'
          ? 'added'
          : f.status === 'renamed'
            ? 'renamed'
            : 'modified';
    const file: GitFile = { path: f.filename, status, text: null };
    if (status === 'renamed' && f.previous_filename) file.previousPath = f.previous_filename;
    if (status === 'removed') return { file, part: null };
    const url = fillTemplate(`${RAW}/${repo}/${head}/{path}`, { path: f.filename });
    try {
      const res = await request(ctx, url);
      file.text = res.text;
      return {
        file,
        part: { url, status: res.status, contentType: res.headers.get('content-type') ?? '', body: res.text },
      };
    } catch (err) {
      if (err instanceof PatternError && err.code === 'http' && (err.status === 404 || err.status === 410))
        return { file, part: null };
      throw err;
    }
  });

  const count = downloaded.done.length;
  if (downloaded.big !== null && count === 0) {
    // A single file over the limit: the job handles it, and the cursor moves past it.
    const f = window[0] as CompareFile;
    const next = advance(base, head, done + 1, tip, allowed.length);
    return heavyResult(ctx, next, {
      kind: 'big-file',
      url: fillTemplate(`${RAW}/${repo}/${head}/{path}`, { path: f.filename }),
      reason: `${f.filename} is over the size limit`,
    });
  }

  const items: RawItem[] = downloaded.done.map(({ file, part }) => {
    if (part) parts.push(part);
    return { id: file.path, body: file };
  });
  if (
    items.length > 0 &&
    items.some((i) => (i.body as GitFile).status === 'removed' || (i.body as GitFile).text === null)
  ) {
    // Removed files come from the compare response, so it is part of the receipt.
    parts.unshift({
      url: `${API}/repos/${repo}/compare/${base}...${head}`,
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        files: window.slice(0, count).map((f) => ({
          filename: f.filename,
          status: f.status,
          ...(f.previous_filename ? { previous_filename: f.previous_filename } : {}),
        })),
      }),
    });
  }

  const nextDone = done + count;
  const nextCursor = advance(base, head, nextDone, tip, allowed.length);
  return {
    items,
    receipt: buildReceipt(ctx, parts),
    nextCursor,
    // A mid-run cursor (more files, or a narrowed range that resumes) means call again.
    more: nextCursor.value.startsWith('{'),
  };
}

/** The cursor after `done` allowed files of `base...head` have been handled. */
function advance(base: string, head: string, done: number, tip: boolean, total: number): Cursor {
  if (done < total) return midCursor({ base, head, done, tip });
  // Range finished. At the branch head: settled. A narrowed range resumes from `head`.
  if (tip) return settled(head);
  return midCursor({ base: head, head, done: 0, tip: false });
}

async function compare(
  ctx: PatternContext,
  repo: string,
  base: string,
  head: string,
): Promise<Compare | 'missing'> {
  const files: CompareFile[] = [];
  let first: Compare | null = null;
  for (let page = 1; page <= COMPARE_FILE_CAP / COMPARE_PAGE; page++) {
    const url = `${fillTemplate(`${API}/repos/${repo}/compare/{base}...{head}`, { base, head })}?per_page=${COMPARE_PAGE}&page=${page}`;
    let res: HttpResult;
    try {
      res = await request(ctx, url, { accept: 'application/vnd.github+json', auth: auth(ctx) });
    } catch (err) {
      if (err instanceof PatternError && err.code === 'http' && (err.status === 404 || err.status === 422))
        return 'missing';
      throw err;
    }
    const doc = parseJson<Compare>(res.text, 'compare');
    first ??= doc;
    files.push(...(doc.files ?? []));
    if ((doc.files?.length ?? 0) < COMPARE_PAGE) break;
  }
  return { ...(first as Compare), files };
}
