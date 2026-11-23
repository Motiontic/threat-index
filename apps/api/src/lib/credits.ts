import type { Credit } from '@ti/core/api';
import { NVD_NOTICE } from '@ti/core/licence';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import type { DisplayMap } from './preview';

/** Legacy shape, kept because the search route is built against it. New code uses `creditsFor`. */
export function credits(sourceIds: string[]): { source: string; text: string }[] {
  const out = sourceIds.map((id) => ({ source: id, text: SOURCE_BY_ID.get(id)?.credit ?? `Source: ${id}` }));
  if (sourceIds.includes('nvd') && !out.some((c) => c.text === NVD_NOTICE))
    out.push({ source: 'nvd', text: NVD_NOTICE });
  return out;
}

/**
 * One credit per unique visible source id, in first-seen order. Hidden and unknown ids are skipped.
 * The `nvd` credit carries the NVD notice and appears once.
 */
export function creditsFor(sourceIds: readonly string[], display: DisplayMap): Credit[] {
  const out: Credit[] = [];
  const seen = new Set<string>();
  for (const id of sourceIds) {
    if (seen.has(id)) continue;
    seen.add(id);
    const source = SOURCE_BY_ID.get(id);
    if (!source) continue;
    const mode = display.get(id) ?? 'hidden';
    if (mode === 'hidden') continue;
    out.push({ sourceId: id, name: source.name, text: id === 'nvd' ? NVD_NOTICE : source.credit });
  }
  return out;
}
