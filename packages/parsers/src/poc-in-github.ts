import { normaliseId } from '@ti/core/ids';
import type { ParseResult, SignalRecord } from '@ti/core/types';
import { isoDay, SAFE_REF } from './exploit-db';

/**
 * PoC-in-GitHub parser. One file per CVE (`<yyyy>/CVE-<id>.json`), a JSON array of GitHub repo
 * objects. Metadata only: the repo name, its creation date and link. Descriptions and owners are
 * never copied; no code is fetched. Worker-safe.
 */

export const MAX_POC_PER_CVE = 25;

const PATH = /(?:^|\/)(CVE-\d{4}-\d{4,})\.json$/;
const FULL_NAME = /^[\w.-]+\/[\w.-]+$/;

const KNOWN_KEYS = new Set([
  'id',
  'name',
  'full_name',
  'owner',
  'html_url',
  'description',
  'fork',
  'created_at',
  'updated_at',
  'pushed_at',
  'stargazers_count',
  'topics',
  'forks',
  'forks_count',
  'watchers',
  'watchers_count',
  'score',
  'subscribers_count',
  'has_discussions',
  'allow_forking',
  'is_template',
  'visibility',
  'web_commit_signoff_required',
  'has_pull_requests',
  'pull_request_creation_policy',
]);

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

export function parsePocInGithub(input: unknown): ParseResult<SignalRecord> & { skipped: number } {
  const empty = { records: [], unknownFields: [], skipped: 0 };
  if (!isObj(input) || typeof input.path !== 'string' || !('text' in input))
    throw new Error('poc-in-github: input must be a GitFile');
  if (input.status === 'removed' || input.text === null || input.text === undefined) return empty;
  const m = PATH.exec(input.path);
  if (!m) return empty;
  if (typeof input.text !== 'string') throw new Error('poc-in-github: GitFile text must be a string');
  let data: unknown;
  try {
    data = JSON.parse(input.text);
  } catch (err) {
    throw new Error('poc-in-github: invalid JSON', { cause: err });
  }
  if (!Array.isArray(data)) throw new Error('poc-in-github: file is not a JSON array');
  const vulnKey = normaliseId(m[1] as string);

  const unknown = new Set<string>();
  const kept: Array<{ fullName: string; day: string; created: number }> = [];
  let skipped = 0;
  for (const e of data) {
    if (!isObj(e)) {
      skipped++;
      continue;
    }
    for (const k of Object.keys(e)) if (!KNOWN_KEYS.has(k)) unknown.add(k);
    if (e.fork === true) continue;
    const fullName = e.full_name;
    const day = isoDay(e.created_at);
    const created = typeof e.created_at === 'string' ? Date.parse(e.created_at) : Number.NaN;
    if (
      typeof fullName !== 'string' ||
      !FULL_NAME.test(fullName) ||
      !SAFE_REF.test(fullName) ||
      e.html_url !== `https://github.com/${fullName}` ||
      !day ||
      Number.isNaN(created)
    ) {
      skipped++;
      continue;
    }
    kept.push({ fullName, day, created });
  }
  kept.sort((a, b) => a.created - b.created);
  const records: SignalRecord[] = kept.slice(0, MAX_POC_PER_CVE).map((k) => ({
    vulnKey,
    kind: 'poc',
    source: 'poc-in-github',
    ref: k.fullName,
    firstSeen: k.day,
    evidenceDate: k.day,
    url: `https://github.com/${k.fullName}`,
  }));
  return { records, unknownFields: [...unknown], skipped };
}

export const parse = parsePocInGithub;
