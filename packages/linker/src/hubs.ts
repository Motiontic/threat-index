import { isCve, vulnKeyFor } from '@ti/core/ids';
import type { AdvisoryRecord, SignalRecord, VulnRecord } from '@ti/core/types';
import { vulnId } from './clean';
import { isAdvisoryRecord, isSignalRecord } from './kinds';

export type HubRecord = VulnRecord | AdvisoryRecord | SignalRecord;

/**
 * The record's IDs through `vulnId`: own ID first, then aliases (or the advisory's vulnKey). Unsafe aliases are
 * dropped. Null when the own ID is unsafe (the record is dropped).
 */
export function candidateIds(r: HubRecord): string[] | null {
  let own: unknown;
  let rest: unknown[];
  if (isAdvisoryRecord(r)) {
    own = r.sourceId;
    rest = [r.vulnKey];
  } else if (isSignalRecord(r)) {
    own = r.vulnKey;
    rest = [];
  } else {
    own = r.key;
    rest = Array.isArray(r.aliases) ? r.aliases : [];
  }
  const first = vulnId(own);
  if (first === null) return null;
  const ids = [first];
  for (const a of rest) {
    const id = vulnId(a);
    if (id !== null && !ids.includes(id)) ids.push(id);
  }
  return ids;
}

/**
 * One hub key per record (null for a record whose own ID is unsafe), by the first rule that applies:
 * 1. its own IDs name a CVE; 2. another record in this call names one of its IDs with a CVE; 3. a stored
 * alias row exists; 4. a stored vulns row exists (smallest ID); 5. its own ID.
 */
export function resolveHubs(
  records: readonly HubRecord[],
  storedAliases: ReadonlyMap<string, string>,
  storedVulnKeys: ReadonlySet<string>,
): (string | null)[] {
  const ids = records.map(candidateIds);
  return records.map((_, i) => {
    const mine = ids[i];
    if (!mine) return null;
    if (mine.some(isCve)) return vulnKeyFor(mine[0] as string, mine.slice(1));
    for (let j = 0; j < records.length; j++) {
      const theirs = ids[j];
      if (j === i || !theirs || !theirs.some(isCve)) continue;
      if (theirs.some((id) => mine.includes(id))) return theirs.find(isCve) as string;
    }
    for (const id of mine) {
      const hub = storedAliases.get(id);
      if (hub) return hub;
    }
    const stored = mine.filter((id) => storedVulnKeys.has(id)).sort();
    return stored[0] ?? (mine[0] as string);
  });
}
