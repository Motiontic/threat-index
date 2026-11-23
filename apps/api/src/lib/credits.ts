import { NVD_NOTICE } from '@ti/core/licence';
import { SOURCE_BY_ID } from '@ti/sources/registry';

export function credits(sourceIds: string[]): { source: string; text: string }[] {
  const out = sourceIds.map((id) => ({ source: id, text: SOURCE_BY_ID.get(id)?.credit ?? `Source: ${id}` }));
  if (sourceIds.includes('nvd') && !out.some((c) => c.text === NVD_NOTICE))
    out.push({ source: 'nvd', text: NVD_NOTICE });
  return out;
}
