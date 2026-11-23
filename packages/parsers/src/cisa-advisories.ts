import { isCve, normaliseId } from '@ti/core/ids';
import type { AdvisoryRecord, ParseResult } from '@ti/core/types';

/**
 * CISA advisories feed (`all.xml`), one item per advisory (the feed pattern's body). One record per
 * CVE the advisory names. Only IDs, the date and the link are kept, never the description.
 */
export const MAX_CVES_PER_ADVISORY = 100;

type Node = Record<string, unknown>;

const KNOWN = new Set(['title', 'link', 'description', 'pubDate', 'guid', 'dc:creator', 'category']);
const KEPT_PATHS = [
  '/news-events/ics-advisories/',
  '/news-events/ics-medical-advisories/',
  '/news-events/cybersecurity-advisories/',
  '/news-events/alerts/',
];
const KEV_TITLE = /^CISA Adds .* Known Exploited Vulnerabilit/i;
const ICS_ID = /^(icsa|icsma)-\d{2}-\d{3}-\d{2}[a-z]?$/i;
const AA_ID = /^aa\d{2}-\d{3}[a-z]$/i;
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const DATE_RE =
  /^(?:[A-Za-z]{3,9},?\s+)?(\d{1,2})\s+([A-Za-z]{3,9})\s+(\d{2}|\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(?:([+-])(\d{2})(\d{2})|(GMT|UTC|UT|Z))$/i;

function textOf(v: unknown): string {
  if (typeof v === 'string') return v.trim();
  if (typeof v === 'number') return String(v);
  if (v && typeof v === 'object' && '#text' in v) return textOf((v as Node)['#text']);
  return '';
}

/** The advisory ID from the link's last path segment, else `CISA-<n>` from a `/node/<n>` guid. */
export function advisoryId(link: string, guid: string): string | null {
  let last = '';
  try {
    const segs = new URL(link).pathname.split('/').filter(Boolean);
    last = segs[segs.length - 1] ?? '';
  } catch {
    last = '';
  }
  if (ICS_ID.test(last) || AA_ID.test(last)) return last.toUpperCase();
  const m = /^\/node\/(\d+)$/.exec(guid.trim());
  return m ? `CISA-${m[1]}` : null;
}

/** RFC 822 date to `YYYY-MM-DDTHH:MM:SS.000Z`; null when it is not one. `yy` means `20yy`. */
function rfc822(s: string): string | null {
  const m = DATE_RE.exec(s.trim());
  if (!m) return null;
  const month = MONTHS.indexOf((m[2] as string).slice(0, 3).toLowerCase());
  if (month < 0) return null;
  const yr = Number(m[3]);
  const year = (m[3] as string).length === 2 ? 2000 + yr : yr;
  const [day, hh, mm, ss] = [Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0)];
  if (hh > 23 || mm > 59 || ss > 59) return null;
  const offset = m[7] ? (m[7] === '-' ? -1 : 1) * (Number(m[8]) * 60 + Number(m[9])) : 0;
  const ms = Date.UTC(year, month, day, hh, mm, ss) - offset * 60000;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return null;
  // Reject days that overflowed (31 Feb) by checking the local fields round-trip.
  const local = new Date(ms + offset * 60000);
  if (local.getUTCDate() !== day || local.getUTCMonth() !== month) return null;
  return `${d.toISOString().slice(0, 19)}.000Z`;
}

export function parseCisaAdvisory(input: unknown): ParseResult<AdvisoryRecord> {
  let value = input;
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      throw new Error('cisa-advisories: input is not valid JSON');
    }
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('cisa-advisories: expected a feed item object');
  }
  const item = value as Node;
  const unknownFields = Object.keys(item).filter((k) => !KNOWN.has(k));
  const title = textOf(item.title);
  const link = textOf(item.link);
  const description = textOf(item.description);
  const guid = textOf(item.guid);

  let url: URL;
  try {
    url = new URL(link);
  } catch {
    throw new Error('cisa-advisories: item has no valid link');
  }
  const isAlert = url.pathname.startsWith('/news-events/alerts/');
  if (
    url.protocol !== 'https:' ||
    url.hostname !== 'www.cisa.gov' ||
    !KEPT_PATHS.some((p) => url.pathname.startsWith(p)) ||
    (isAlert && KEV_TITLE.test(title))
  ) {
    return { records: [], unknownFields };
  }

  const id = advisoryId(link, guid);
  if (id === null) throw new Error('cisa-advisories: cannot derive an advisory ID');
  const date = rfc822(textOf(item.pubDate));
  if (date === null) throw new Error('cisa-advisories: invalid pubDate');

  const cves = new Set<string>();
  for (const text of [title, description]) {
    for (const m of text.matchAll(/CVE-\d{4}-\d{4,}/gi)) {
      if (cves.size >= MAX_CVES_PER_ADVISORY) break;
      if (isCve(m[0])) cves.add(normaliseId(m[0]));
    }
  }

  const records: AdvisoryRecord[] = [...cves].map((cve) => ({
    source: 'cisa-advisories',
    sourceId: `${id}:${cve}`,
    vulnKey: cve,
    status: 'active',
    published: date,
    modified: date,
    url: link,
  }));
  return { records, unknownFields };
}

export const parse = parseCisaAdvisory;
