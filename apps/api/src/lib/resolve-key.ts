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

export async function resolveKey(env: Pick<Bindings, 'DB_ADVISORIES'>, id: string): Promise<string> {
  const source = PREFIX_SOURCE.find(([re]) => re.test(id))?.[1];
  if (!source) return id;
  const row = await env.DB_ADVISORIES.prepare(
    'SELECT vuln_key FROM advisories WHERE source = ?1 AND source_id = ?2',
  )
    .bind(source, id)
    .first<{ vuln_key: string | null }>();
  return row?.vuln_key ?? id;
}
