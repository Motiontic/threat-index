import type { NoticeRecord, ParseResult } from '@ti/core/types';
import { bodies, cleanName, isoDay, noteUnknown } from './notice-us';

const KNOWN = new Set(['title', 'link', 'summary', 'updated', 'category', 'id']);
const ACCESSION = /^\d{10}-\d{2}-\d{6}$/;
const ARCHIVES = 'https://www.sec.gov/Archives/edgar/data/';

const text = (v: unknown): string => {
  if (typeof v === 'string') return v;
  if (typeof v === 'number') return String(v);
  if (v && typeof v === 'object' && '#text' in v) return text((v as Record<string, unknown>)['#text']);
  return '';
};
const first = (v: unknown): unknown => (Array.isArray(v) ? v[0] : v);
const attr = (v: unknown, name: string): string => {
  const o = first(v);
  return o && typeof o === 'object' ? text((o as Record<string, unknown>)[name]) : '';
};

/** SEC EDGAR current 8-K Atom entries. Only 8-K and 8-K/A entries that list Item 1.05 give a record. */
export function parseSecEdgar(input: unknown): ParseResult<NoticeRecord> & { skipped: number } {
  const records: NoticeRecord[] = [];
  const unknown = new Set<string>();
  let skipped = 0;
  for (const entry of bodies(input, 'sec-edgar')) {
    noteUnknown(entry, KNOWN, unknown);
    const title = text(entry.title).trim();
    const t = /^(8-K(?:\/A)?) - (.+?) \((\d{10})\)/.exec(title);
    const form = attr(entry.category, '@_term') || t?.[1] || '';
    if (form !== '8-K' && form !== '8-K/A') continue;
    const summary = text(entry.summary).replace(/<[^>]*>/g, ' ');
    if (!/\bItem 1\.05\b/.test(summary)) continue;

    const acc =
      /AccNo:\s*(\d{10}-\d{2}-\d{6})/.exec(summary)?.[1] ??
      /accession-number=(\S+)$/.exec(text(entry.id).trim())?.[1];
    const rawName = cleanName(t?.[2]);
    const href = attr(entry.link, '@_href');
    const linkCik = href.startsWith(ARCHIVES) ? /^(\d+)\//.exec(href.slice(ARCHIVES.length))?.[1] : undefined;
    if (
      !acc ||
      !ACCESSION.test(acc) ||
      !t ||
      !rawName ||
      linkCik === undefined ||
      Number(linkCik) !== Number(t[3])
    ) {
      skipped++;
      continue;
    }
    const notified = /Filed:\s*(\d{4}-\d{2}-\d{2})/.exec(summary)?.[1];
    const filed = (notified && isoDay(notified)) || isoDay(text(entry.updated));
    records.push({
      source: 'sec-edgar',
      noticeId: acc,
      rawName,
      companyKey: `cik:${t[3]}`,
      ...(filed ? { notified: filed } : {}),
      countUnit: 'not_stated',
      jurisdiction: 'US',
      url: href,
    });
  }
  return { records, unknownFields: [...unknown], skipped };
}

export const parse = parseSecEdgar;
