import type { Credit } from '@ti/core/api';
import { NVD_NOTICE } from '@ti/core/licence';
import { SOURCE_BY_ID } from '@ti/sources/registry';

/** Credits for the union of `sources` over a page of hits, in first-seen order. Always an array. */
export function searchCredits(sourceLists: string[][]): Credit[] {
  const ids: string[] = [];
  for (const list of sourceLists) for (const id of list) if (!ids.includes(id)) ids.push(id);
  const out: Credit[] = ids.map((id) => {
    const s = SOURCE_BY_ID.get(id);
    return { sourceId: id, name: s?.name ?? id, text: s?.credit ?? `Source: ${id}` };
  });
  if (ids.includes('nvd') && !out.some((c) => c.text === NVD_NOTICE))
    out.push({ sourceId: 'nvd', name: SOURCE_BY_ID.get('nvd')?.name ?? 'nvd', text: NVD_NOTICE });
  return out;
}

export function parseSources(raw: unknown): string[] {
  if (typeof raw !== 'string') return [];
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}
