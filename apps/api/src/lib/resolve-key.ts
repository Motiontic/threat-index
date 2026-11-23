import { normaliseId } from '@ti/core/ids';
import type { Bindings } from './env';

/** Which source owns an ID prefix, so any alias resolves through the advisories primary key. */
const PREFIX_SOURCE: [RegExp, string][] = [
  [/^GHSA-/, 'github-advisory-db'],
  [/^RHSA-/, 'red-hat'],
  [/^USN-/, 'ubuntu'],
  [/^(DSA|DLA)-/, 'debian'],
  [/^JVNDB-/, 'jvn'],
  [/^EUVD-/, 'enisa'],
  [/^(PYSEC|GO|RUSTSEC|MAL)-/, 'osv'],
];

const ID_CHARS = /^[A-Za-z0-9._:-]+$/;

/** The normalised id, or null when it is too long, empty or has a character outside [A-Za-z0-9._:-]. */
export function validId(raw: string): string | null {
  const id = normaliseId(raw);
  return id.length > 0 && id.length <= 128 && ID_CHARS.test(id) ? id : null;
}

/** Resolves any id or alias to a `vulns.key`. Null means not found (or an invalid id). */
export async function resolveKey(
  env: Pick<Bindings, 'DB_ADVISORIES' | 'DB_VULNS'>,
  raw: string,
): Promise<string | null> {
  const id = validId(raw);
  if (!id) return null;
  const exists = (key: string) =>
    env.DB_VULNS.prepare('SELECT key FROM vulns WHERE key = ?1').bind(key).first<{ key: string }>();

  if (await exists(id)) return id;

  const prefixSource = PREFIX_SOURCE.find(([re]) => re.test(id))?.[1];
  const lookup = (source: string) =>
    env.DB_ADVISORIES.prepare('SELECT vuln_key FROM advisories WHERE source = ?1 AND source_id = ?2').bind(
      source,
      id,
    );
  const stmts = [lookup('alias')];
  if (prefixSource) stmts.push(lookup(prefixSource));
  const results = await env.DB_ADVISORIES.batch<{ vuln_key: string | null }>(stmts);
  for (const r of results) {
    const key = r.results[0]?.vuln_key;
    if (key && (await exists(key))) return key;
  }
  return null;
}
