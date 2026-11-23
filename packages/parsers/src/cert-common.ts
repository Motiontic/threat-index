import { isCve, normaliseId } from '@ti/core/ids';
import type { AdvisoryRecord } from '@ti/core/types';

/**
 * Helpers shared by the national-CERT parsers (CERT/CC, JVN, BSI CERT-Bund). No `parse` here, so this file is
 * not a parser module. No Node-only imports: runs in Workers and E2B.
 */

/** A roll-up advisory can list hundreds of CVEs (one JVN item had 647). Cap what one advisory may fan out to. */
export const MAX_CVES_PER_ADVISORY = 1000;

/** The linker's id rule (`vulnId` in packages/linker/src/clean.ts): a record whose `sourceId` fails is dropped. */
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const ISO = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*(Z|[+-]\d{2}:?\d{2})$/;

/** ISO 8601 with or without seconds, any fraction, `Z`, `±hh:mm` or `±hhmm` → `YYYY-MM-DDTHH:MM:SS.sssZ`; else null. */
export function isoMs(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const m = ISO.exec(raw.trim());
  if (!m) return null;
  const [y, mo, d, hh, mm] = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])];
  const ss = m[6] === undefined ? 0 : Number(m[6]);
  const ms = m[7] === undefined ? 0 : Number(m[7].slice(0, 3).padEnd(3, '0'));
  if (hh > 23 || mm > 59 || ss > 59) return null;
  let offset = 0;
  const tz = m[8] as string;
  if (tz !== 'Z') {
    const oh = Number(tz.slice(1, 3));
    const om = Number(tz.slice(-2));
    if (oh > 23 || om > 59) return null;
    offset = (tz[0] === '-' ? -1 : 1) * (oh * 60 + om);
  }
  // setUTCFullYear keeps years 0-99 as written; the round trip rejects 31 Feb and month 13.
  const t = new Date(0);
  t.setUTCFullYear(y, mo - 1, d);
  if (t.getUTCFullYear() !== y || t.getUTCMonth() !== mo - 1 || t.getUTCDate() !== d) return null;
  t.setUTCHours(hh, mm, ss, ms);
  const out = new Date(t.getTime() - offset * 60_000);
  return Number.isNaN(out.getTime()) ? null : out.toISOString();
}

/** Normalised, unique (first seen wins), valid CVE ids; at most MAX_CVES_PER_ADVISORY. */
export function cveList(raw: readonly unknown[]): string[] {
  const out = new Set<string>();
  for (const v of raw) {
    if (out.size >= MAX_CVES_PER_ADVISORY) break;
    if (typeof v !== 'string') continue;
    const t = v.trim();
    if (isCve(t)) out.add(normaliseId(t));
  }
  return [...out];
}

const checkId = (id: string): string => {
  if (!SAFE_ID.test(normaliseId(id))) throw new Error(`cert: unsafe advisory id ${JSON.stringify(id)}`);
  return id;
};

/** One AdvisoryRecord per CVE (`sourceId` `<baseId>:<CVE>`), or one with `vulnKey: null` and `sourceId` `<baseId>`. */
export function perCve(
  baseId: string,
  cves: readonly string[],
  fields: Omit<AdvisoryRecord, 'sourceId' | 'vulnKey'>,
): AdvisoryRecord[] {
  checkId(baseId);
  if (cves.length === 0) return [{ ...fields, sourceId: baseId, vulnKey: null }];
  return cves.map((cve) => ({ ...fields, sourceId: checkId(`${baseId}:${cve}`), vulnKey: cve }));
}
