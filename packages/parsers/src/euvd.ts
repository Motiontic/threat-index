import { isCve, normaliseId } from '@ti/core/ids';
import type { AdvisoryRecord, ParseResult, SignalRecord, VulnRecord } from '@ti/core/types';
import { z } from 'zod';

/** ENISA EU Vulnerability Database (EUVD). No stated licence; source marked `ask`. */
const Entry = z.looseObject({
  id: z.unknown(),
  enisaUuid: z.unknown().optional(),
  description: z.unknown().optional(),
  datePublished: z.unknown().optional(),
  dateUpdated: z.unknown().optional(),
  baseScore: z.unknown().optional(),
  baseScoreVersion: z.unknown().optional(),
  baseScoreVector: z.unknown().optional(),
  references: z.unknown().optional(),
  aliases: z.unknown().optional(),
  assigner: z.unknown().optional(),
  epss: z.unknown().optional(),
  exploitedSince: z.unknown().optional(),
  enisaIdProduct: z.unknown().optional(),
  enisaIdVendor: z.unknown().optional(),
  enisaIdVulnerability: z.unknown().optional(),
  enisaIdAdvisory: z.unknown().optional(),
});

const KNOWN_ENTRY = new Set(Object.keys(Entry.shape));
const KNOWN_TOP = new Set(['items', 'total']);

const EUVD_ID = /^EUVD-\d{4}-\d+$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CVSS_VERSIONS = new Set(['2.0', '3.0', '3.1', '4.0']);

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const EUVD_DATE =
  /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{1,2}), (\d{4}), (\d{1,2}):(\d{2}):(\d{2}) (AM|PM)$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;

/** `Nov 20, 2026, 10:30:42 PM` (UTC) or an ISO 8601 string to an ISO timestamp; anything else, or an impossible date, null. */
export function parseEuvdDate(raw: string): string | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  const m = EUVD_DATE.exec(s);
  if (m) {
    const month = MONTHS.indexOf(m[1] as string);
    const day = Number(m[2]);
    const year = Number(m[3]);
    const h12 = Number(m[4]);
    const min = Number(m[5]);
    const sec = Number(m[6]);
    if (h12 < 1 || h12 > 12 || min > 59 || sec > 59) return null;
    const hour = (h12 % 12) + (m[7] === 'PM' ? 12 : 0);
    const d = new Date(Date.UTC(year, month, day, hour, min, sec));
    if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month || d.getUTCDate() !== day) return null;
    return d.toISOString();
  }
  if (ISO_DATE.test(s)) {
    const y = Number(s.slice(0, 4));
    const mo = Number(s.slice(5, 7));
    const dd = Number(s.slice(8, 10));
    if (mo < 1 || mo > 12 || dd < 1 || dd > new Date(Date.UTC(y, mo, 0)).getUTCDate()) return null;
    const d = new Date(s);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  return null;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const collapse = (s: string) => s.replace(/\s+/g, ' ').trim();

function summaryOf(text: string): string {
  if (text.length <= 300) return text;
  const cut = text.slice(0, 300);
  const sp = cut.lastIndexOf(' ');
  return (sp > 0 ? cut.slice(0, sp) : cut).trimEnd();
}

function titleOf(text: string, id: string): string {
  const m = /^(.+?[.!?])(?:\s|$)/.exec(text);
  const first = m?.[1];
  if (first && first.length <= 120) return first;
  if (!m && text.length > 0 && text.length <= 120) return text;
  return id;
}

type Out = VulnRecord | AdvisoryRecord | SignalRecord;

export function parseEuvd(input: unknown): ParseResult<Out> {
  let doc = input;
  if (typeof doc === 'string') {
    try {
      doc = JSON.parse(doc);
    } catch {
      throw new Error('euvd: input is not valid JSON');
    }
  }

  const unknown = new Set<string>();
  let entries: unknown[];
  if (Array.isArray(doc)) {
    entries = doc;
  } else if (isObject(doc) && Array.isArray(doc.items)) {
    entries = doc.items;
    for (const key of Object.keys(doc)) if (!KNOWN_TOP.has(key)) unknown.add(key);
  } else if (isObject(doc) && 'id' in doc) {
    entries = [doc];
  } else {
    throw new Error('euvd: expected a search response, an array of entries or a single entry');
  }

  const records: Out[] = [];
  for (const item of entries) {
    const parsed = Entry.safeParse(item);
    if (!parsed.success) continue;
    const e = parsed.data;
    for (const key of Object.keys(e)) if (!KNOWN_ENTRY.has(key)) unknown.add(key);

    if (typeof e.id !== 'string' || !EUVD_ID.test(e.id)) continue;
    const id = e.id;
    const modified = typeof e.dateUpdated === 'string' ? parseEuvdDate(e.dateUpdated) : null;
    if (!modified) throw new Error(`euvd: ${id}: missing or invalid dateUpdated`);
    const published = typeof e.datePublished === 'string' ? parseEuvdDate(e.datePublished) : null;

    const aliases: string[] = [];
    if (typeof e.aliases === 'string') {
      for (const part of e.aliases.split(/\s+/)) {
        if (!part) continue;
        const a = normaliseId(part);
        if (a !== id && SAFE_ID.test(a) && !aliases.includes(a)) aliases.push(a);
      }
    }
    const cve = aliases.find(isCve) ?? null;
    const url = `https://euvd.enisa.europa.eu/vulnerability/${id}`;

    records.push({
      source: 'enisa',
      sourceId: id,
      vulnKey: cve,
      status: 'active',
      ...(published ? { published } : {}),
      modified,
      url,
    });

    if (!cve) {
      const text = typeof e.description === 'string' ? collapse(e.description) : '';
      const score = typeof e.baseScore === 'number' ? e.baseScore : null;
      const version = typeof e.baseScoreVersion === 'string' ? e.baseScoreVersion : null;
      const hasScore =
        score !== null &&
        Number.isFinite(score) &&
        score >= 0 &&
        score <= 10 &&
        version !== null &&
        CVSS_VERSIONS.has(version);
      records.push({
        key: id,
        kind: 'euvd',
        source: 'enisa',
        title: titleOf(text, id),
        summary: summaryOf(text),
        ...(published ? { published } : {}),
        modified,
        ...(hasScore ? { cvss: score, cvssVersion: version } : {}),
        ...(typeof e.assigner === 'string' && e.assigner ? { cvssSource: e.assigner } : {}),
        cwe: [],
        aliases,
      });
    }

    const since = typeof e.exploitedSince === 'string' ? parseEuvdDate(e.exploitedSince) : null;
    if (since) {
      const d = since.slice(0, 10);
      records.push({
        vulnKey: cve ?? id,
        kind: 'exploited_wild',
        source: 'enisa',
        ref: id,
        firstSeen: d,
        evidenceDate: d,
        url,
      });
    }
  }
  return { records, unknownFields: [...unknown] };
}

/** The parser-module contract: `@ti/parsers/<name>` exports `parse`. */
export const parse = parseEuvd;
