import type { ParseResult, SignalRecord } from '@ti/core';
import { normaliseId } from '@ti/core';
import { z } from 'zod';

/** CISA Known Exploited Vulnerabilities catalogue (JSON feed). CC0. */
const KevEntry = z.looseObject({
  cveID: z.string(),
  vendorProject: z.string(),
  product: z.string(),
  vulnerabilityName: z.string(),
  dateAdded: z.string(),
  shortDescription: z.string().optional(),
  requiredAction: z.string().optional(),
  dueDate: z.string().optional(),
  knownRansomwareCampaignUse: z.string().optional(),
  notes: z.string().optional(),
  cwes: z.array(z.string()).optional(),
});

const KevCatalog = z.looseObject({
  catalogVersion: z.string(),
  dateReleased: z.string(),
  vulnerabilities: z.array(KevEntry),
});

const KNOWN_ENTRY_FIELDS = new Set(Object.keys(KevEntry.shape));

export function parseKev(json: unknown): ParseResult<SignalRecord> & { catalogVersion: string } {
  const catalog = KevCatalog.parse(json);
  const unknown = new Set<string>();
  const records: SignalRecord[] = [];

  for (const v of catalog.vulnerabilities) {
    for (const key of Object.keys(v)) if (!KNOWN_ENTRY_FIELDS.has(key)) unknown.add(key);
    const vulnKey = normaliseId(v.cveID);
    records.push({
      vulnKey,
      kind: 'exploited_wild',
      source: 'cisa-kev',
      ref: vulnKey,
      firstSeen: v.dateAdded,
      evidenceDate: v.dateAdded,
    });
    if (v.knownRansomwareCampaignUse === 'Known') {
      records.push({ vulnKey, kind: 'ransomware', source: 'cisa-kev', ref: vulnKey, firstSeen: v.dateAdded });
    }
  }

  return { records, unknownFields: [...unknown], catalogVersion: catalog.catalogVersion };
}
