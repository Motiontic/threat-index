import type { TechniqueRecord } from '@ti/core/types';
import { differs, text } from '../clean';
import type { Row } from '../tables';

/** The full row, or null when it would not change. Techniques carry no `modified`. */
export function techniqueRow(r: TechniqueRecord, stored: Row | undefined): Row | null {
  const row: Row = {
    id: r.id,
    framework: r.framework,
    name: r.name,
    parent: text(r.parent) ?? stored?.parent ?? null,
    summary: text(r.summary) ?? stored?.summary ?? null,
  };
  return differs(row, stored) ? row : null;
}
