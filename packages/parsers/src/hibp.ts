import type { NoticeRecord, ParseResult } from '@ti/core/types';
import { z } from 'zod';

/**
 * Have I Been Pwned `/api/v3/breaches`, one breach object per item (the fingerprint pattern's body).
 * Only metadata is kept: name, date, count, data types and a link. Never the description, logo,
 * attribution or disclosure URL. CC BY 4.0.
 */
export const MAX_DATA_TYPES = 30;

const Breach = z.looseObject({
  Name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/),
  Title: z.string(),
  PwnCount: z.number().int().nonnegative(),
  DataClasses: z.array(z.string()),
  IsVerified: z.boolean(),
  IsFabricated: z.boolean(),
  IsSensitive: z.boolean(),
  IsRetired: z.boolean(),
  IsSpamList: z.boolean(),
  IsMalware: z.boolean(),
  IsSubscriptionFree: z.boolean(),
  IsStealerLog: z.boolean(),
  BreachDate: z.unknown().optional(),
});

const KNOWN = new Set([
  'Name',
  'Title',
  'Domain',
  'BreachDate',
  'AddedDate',
  'ModifiedDate',
  'PwnCount',
  'Description',
  'LogoPath',
  'Attribution',
  'DisclosureUrl',
  'DataClasses',
  'IsVerified',
  'IsFabricated',
  'IsSensitive',
  'IsRetired',
  'IsSpamList',
  'IsMalware',
  'IsSubscriptionFree',
  'IsStealerLog',
]);

const DAY = /^\d{4}-\d{2}-\d{2}$/;

function validDay(v: unknown): string | null {
  if (typeof v !== 'string' || !DAY.test(v)) return null;
  const d = new Date(`${v}T00:00:00.000Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === v ? v : null;
}

export function parseHibp(input: unknown): ParseResult<NoticeRecord> {
  let value = input;
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      throw new Error('hibp: input is not valid JSON');
    }
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('hibp: expected a breach object');
  }
  const b = Breach.parse(value);
  const unknownFields = Object.keys(b).filter((k) => !KNOWN.has(k));

  if (
    !b.IsVerified ||
    b.IsFabricated ||
    b.IsSpamList ||
    b.IsSensitive ||
    b.IsRetired ||
    b.IsMalware ||
    b.IsStealerLog
  ) {
    return { records: [], unknownFields };
  }

  const dataTypes = [...new Set(b.DataClasses.map((s) => s.trim()).filter((s) => s !== ''))].slice(
    0,
    MAX_DATA_TYPES,
  );
  const day = validDay(b.BreachDate);
  const record: NoticeRecord = {
    source: 'hibp',
    noticeId: b.Name,
    rawName: b.Title.trim() || b.Name,
    ...(day ? { occurredFrom: day } : {}),
    count: b.PwnCount,
    countUnit: 'accounts',
    dataTypes,
    url: `https://haveibeenpwned.com/Breach/${b.Name}`,
  };
  return { records: [record], unknownFields };
}

export const parse = parseHibp;
