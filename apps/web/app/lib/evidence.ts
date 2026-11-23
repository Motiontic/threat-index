// Groups an entry's signals by kind. The four groups stay apart and are never merged into one score.
import type { EntryFullView } from '../data/types';

export interface EvidenceItem {
  source: string;
  ref: string;
  firstSeen: string;
  url?: string;
}
export interface EvidenceGroup {
  id: 'exploited' | 'exploit-code' | 'detections' | 'other';
  title: string;
  note: string;
  items: EvidenceItem[];
  /** The KEV date, shown with the exploited group. */
  kevAdded?: string;
}
export interface Evidence {
  groups: EvidenceGroup[];
  /** EPSS is a probability of future exploitation, not evidence; shown on its own. */
  prediction: { epss: number } | null;
}

const GROUP_OF: Record<string, EvidenceGroup['id']> = {
  exploited_wild: 'exploited',
  ransomware: 'exploited',
  public_exploit: 'exploit-code',
  poc: 'exploit-code',
  detection: 'detections',
};

const TITLES: Record<EvidenceGroup['id'], { title: string; note: string }> = {
  exploited: { title: 'Exploited in the wild', note: 'Reported as used in real attacks.' },
  'exploit-code': {
    title: 'Public exploit code',
    note: 'Metadata and links only; the code itself is not copied here.',
  },
  detections: { title: 'Detections', note: 'Rules that can detect this issue.' },
  other: { title: 'Other signals', note: 'Signals of a kind this page does not know yet.' },
};

export function groupEvidence(entry: Pick<EntryFullView, 'signals' | 'kevAdded' | 'epss'>): Evidence {
  const byId = new Map<EvidenceGroup['id'], EvidenceGroup>();
  const add = (id: EvidenceGroup['id'], item: EvidenceItem) => {
    let g = byId.get(id);
    if (!g) {
      g = { id, ...TITLES[id], items: [] };
      byId.set(id, g);
    }
    g.items.push(item);
  };
  for (const s of entry.signals) {
    const item: EvidenceItem = { source: s.source, ref: s.ref, firstSeen: s.firstSeen };
    if (s.url) item.url = s.url;
    add(GROUP_OF[s.kind] ?? 'other', item);
  }
  if (entry.kevAdded && !byId.has('exploited'))
    byId.set('exploited', { id: 'exploited', ...TITLES.exploited, items: [] });
  const exploited = byId.get('exploited');
  if (exploited && entry.kevAdded) exploited.kevAdded = entry.kevAdded;
  const order: EvidenceGroup['id'][] = ['exploited', 'exploit-code', 'detections', 'other'];
  return {
    groups: order.flatMap((id) => {
      const g = byId.get(id);
      return g ? [g] : [];
    }),
    prediction: entry.epss === undefined ? null : { epss: entry.epss },
  };
}
