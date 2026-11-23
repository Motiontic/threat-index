import type { NoticeRecord } from '@ti/core/types';

/**
 * A labelled set of breach notices for breach-set.test.ts.
 *
 * The notices are HAND-WRITTEN and APPROXIMATE. They are modelled on public incidents from 2023-2024
 * (Change Healthcare, AT&T, Ticketmaster, 23andMe, MGM, Clorox, Caesars, Prudential, HPE, Frontier), but
 * the dates, counts, jurisdictions and name variants are not copied from any filing and must not be quoted
 * as facts about those incidents.
 *
 * The CIKs are UNVERIFIED: SEC EDGAR answered 403 (rate-limit page) to every request from the build
 * sandbox, so none could be looked up. They are recalled from memory and must be checked on EDGAR before
 * anyone relies on them outside this test. The test only needs them to be distinct and well-formed.
 *
 * `expect.companyKey` is the company the notice should resolve to, `expect.event` a label: notices with the
 * same label belong to one event, notices with different labels to different events. `miss: true` marks a
 * notice the matcher is known to fail on (a notice filed under a subsidiary name).
 */
export interface LabelledNotice {
  record: NoticeRecord;
  expect: { companyKey: string; event: string; miss?: true };
}

const CIK = {
  unh: '0000731766', // UnitedHealth Group Incorporated (unverified)
  att: '0000732717', // AT&T Inc. (unverified)
  ln: '0001335258', // Live Nation Entertainment, Inc. (unverified)
  w23: '0001804591', // 23andMe Holding Co. (unverified)
  mgm: '0000789570', // MGM Resorts International (unverified)
  clx: '0000021076', // The Clorox Company (unverified)
  czr: '0001590895', // Caesars Entertainment, Inc. (unverified)
  pru: '0001137774', // Prudential Financial, Inc. (unverified)
  hpe: '0001645590', // Hewlett Packard Enterprise Company (unverified)
  ftr: '0000020520', // Frontier Communications Parent, Inc. (unverified)
} as const;
type Co = keyof typeof CIK;
const key = (c: Co) => `cik:${CIK[c]}`;

/** An 8-K Item 1.05: the filer's name, a CIK hint, a discovery date, no count. */
const sec = (id: string, c: Co, rawName: string, discovered: string): LabelledNotice => ({
  record: {
    source: 'sec-8k',
    noticeId: id,
    rawName,
    companyKey: `cik:${Number(CIK[c])}`, // unpadded, as a parser may emit it
    discovered,
    countUnit: 'not_stated',
  },
  expect: { companyKey: key(c), event: c },
});

interface AgOpts {
  source: string;
  id: string;
  c: Co;
  name: string;
  juris: string;
  from: string;
  to: string;
  notified: string;
  unit: 'state_residents' | 'individuals';
  count: number;
  miss?: true;
}
const ag = (o: AgOpts): LabelledNotice => ({
  record: {
    source: o.source,
    noticeId: o.id,
    rawName: o.name,
    jurisdiction: o.juris,
    occurredFrom: o.from,
    occurredTo: o.to,
    notified: o.notified,
    count: o.count,
    countUnit: o.unit,
  },
  expect: { companyKey: key(o.c), event: o.c, ...(o.miss ? { miss: true as const } : {}) },
});

/** A notice with no hint whose label is the name key it should get. */
const small = (
  source: string,
  id: string,
  rawName: string,
  juris: string,
  from: string,
  to: string,
  count: number,
  companyKey: string,
  event: string,
): LabelledNotice => ({
  record: {
    source,
    noticeId: id,
    rawName,
    jurisdiction: juris,
    occurredFrom: from,
    occurredTo: to,
    notified: to,
    count,
    countUnit: 'state_residents',
  },
  expect: { companyKey, event },
});

export const BREACH_SET: LabelledNotice[] = [
  // --- 10 SEC notices with a cik: hint ---
  sec('0001', 'unh', 'UnitedHealth Group Incorporated', '2024-02-21'),
  sec('0002', 'att', 'AT&T Inc.', '2024-04-19'),
  sec('0003', 'ln', 'Live Nation Entertainment, Inc.', '2024-05-20'),
  sec('0004', 'w23', '23andMe Holding Co.', '2023-10-06'),
  sec('0005', 'mgm', 'MGM Resorts International', '2023-09-10'),
  sec('0006', 'clx', 'THE CLOROX COMPANY', '2023-08-11'),
  sec('0007', 'czr', 'Caesars Entertainment, Inc.', '2023-09-07'),
  sec('0008', 'pru', 'Prudential Financial, Inc.', '2024-02-04'),
  sec('0009', 'hpe', 'Hewlett Packard Enterprise Company', '2023-12-12'),
  sec('0010', 'ftr', 'Frontier Communications Parent, Inc.', '2024-04-14'),

  // --- 22 state AG / HHS notices for the same companies, with name variants ---
  ag({
    source: 'hhs-ocr',
    id: 'h1',
    c: 'unh',
    name: 'UnitedHealth Group, Inc.',
    juris: 'US',
    from: '2024-02-17',
    to: '2024-02-21',
    notified: '2024-07-19',
    unit: 'individuals',
    count: 100_000_000,
  }),
  ag({
    source: 'wa-ag',
    id: 'w1',
    c: 'unh',
    name: 'The UnitedHealth Group Incorporated',
    juris: 'US-WA',
    from: '2024-02-17',
    to: '2024-02-21',
    notified: '2024-08-02',
    unit: 'state_residents',
    count: 91_000,
  }),

  ag({
    source: 'ca-ag',
    id: 'c1',
    c: 'att',
    name: 'AT&T',
    juris: 'US-CA',
    from: '2024-04-14',
    to: '2024-04-25',
    notified: '2024-07-12',
    unit: 'state_residents',
    count: 1_500_000,
  }),
  ag({
    source: 'wa-ag',
    id: 'w2',
    c: 'att',
    name: 'AT & T Inc',
    juris: 'US-WA',
    from: '2024-04-14',
    to: '2024-04-25',
    notified: '2024-07-15',
    unit: 'state_residents',
    count: 480_000,
  }),
  ag({
    source: 'me-ag',
    id: 'm1',
    c: 'att',
    name: 'AT&T INC.',
    juris: 'US-ME',
    from: '2024-04-14',
    to: '2024-04-25',
    notified: '2024-07-16',
    unit: 'individuals',
    count: 73_000_000,
  }),

  ag({
    source: 'ca-ag',
    id: 'c2',
    c: 'ln',
    name: 'Live Nation Entertainment',
    juris: 'US-CA',
    from: '2024-04-02',
    to: '2024-05-20',
    notified: '2024-07-02',
    unit: 'state_residents',
    count: 2_100_000,
  }),
  ag({
    source: 'tx-ag',
    id: 't1',
    c: 'ln',
    name: 'LIVE NATION ENTERTAINMENT INC',
    juris: 'US-TX',
    from: '2024-04-02',
    to: '2024-05-20',
    notified: '2024-07-03',
    unit: 'individuals',
    count: 560_000,
  }),

  ag({
    source: 'ca-ag',
    id: 'c3',
    c: 'w23',
    name: '23andMe Holding Company',
    juris: 'US-CA',
    from: '2023-04-29',
    to: '2023-09-27',
    notified: '2023-12-01',
    unit: 'state_residents',
    count: 800_000,
  }),
  ag({
    source: 'wa-ag',
    id: 'w3',
    c: 'w23',
    name: '23ANDME HOLDING CO.',
    juris: 'US-WA',
    from: '2023-04-29',
    to: '2023-09-27',
    notified: '2023-12-04',
    unit: 'state_residents',
    count: 61_000,
  }),
  // a notice filed under the operating subsidiary's name: the matcher cannot know it is 23andMe
  ag({
    source: 'me-ag',
    id: 'm2',
    c: 'w23',
    name: '23andMe, Inc.',
    juris: 'US-ME',
    from: '2023-04-29',
    to: '2023-09-27',
    notified: '2023-12-05',
    unit: 'individuals',
    count: 6_900_000,
    miss: true,
  }),

  ag({
    source: 'ca-ag',
    id: 'c4',
    c: 'mgm',
    name: 'MGM Resorts International',
    juris: 'US-CA',
    from: '2023-09-08',
    to: '2023-09-11',
    notified: '2023-10-06',
    unit: 'state_residents',
    count: 410_000,
  }),
  ag({
    source: 'tx-ag',
    id: 't2',
    c: 'mgm',
    name: 'MGM RESORTS INTERNATIONAL.',
    juris: 'US-TX',
    from: '2023-09-08',
    to: '2023-09-11',
    notified: '2023-10-09',
    unit: 'individuals',
    count: 1_300_000,
  }),

  ag({
    source: 'ca-ag',
    id: 'c5',
    c: 'clx',
    name: 'The Clorox Co.',
    juris: 'US-CA',
    from: '2023-08-10',
    to: '2023-08-11',
    notified: '2023-09-20',
    unit: 'state_residents',
    count: 9_000,
  }),
  ag({
    source: 'tx-ag',
    id: 't3',
    c: 'clx',
    name: 'Clorox Company',
    juris: 'US-TX',
    from: '2023-08-10',
    to: '2023-08-11',
    notified: '2023-09-22',
    unit: 'state_residents',
    count: 4_000,
  }),

  ag({
    source: 'ca-ag',
    id: 'c6',
    c: 'czr',
    name: 'Caesars Entertainment Inc',
    juris: 'US-CA',
    from: '2023-09-07',
    to: '2023-09-07',
    notified: '2023-10-12',
    unit: 'state_residents',
    count: 1_100_000,
  }),
  ag({
    source: 'me-ag',
    id: 'm3',
    c: 'czr',
    name: 'CAESARS ENTERTAINMENT, INC.',
    juris: 'US-ME',
    from: '2023-09-07',
    to: '2023-09-07',
    notified: '2023-10-13',
    unit: 'individuals',
    count: 41_000_000,
  }),

  ag({
    source: 'ca-ag',
    id: 'c7',
    c: 'pru',
    name: 'Prudential Financial, Inc.',
    juris: 'US-CA',
    from: '2024-02-04',
    to: '2024-02-05',
    notified: '2024-04-01',
    unit: 'state_residents',
    count: 150_000,
  }),
  ag({
    source: 'wa-ag',
    id: 'w4',
    c: 'pru',
    name: 'Prudential Financial',
    juris: 'US-WA',
    from: '2024-02-04',
    to: '2024-02-05',
    notified: '2024-04-02',
    unit: 'state_residents',
    count: 27_000,
  }),
  ag({
    source: 'hhs-ocr',
    id: 'h2',
    c: 'pru',
    name: 'Prudential Financial, Inc. d/b/a Prudential',
    juris: 'US',
    from: '2024-02-04',
    to: '2024-02-05',
    notified: '2024-04-05',
    unit: 'individuals',
    count: 2_500_000,
  }),

  ag({
    source: 'ca-ag',
    id: 'c8',
    c: 'hpe',
    name: 'Hewlett-Packard Enterprise Co.',
    juris: 'US-CA',
    from: '2023-12-12',
    to: '2024-01-12',
    notified: '2024-02-20',
    unit: 'state_residents',
    count: 1_000,
  }),

  ag({
    source: 'me-ag',
    id: 'm4',
    c: 'ftr',
    name: 'FRONTIER COMMUNICATIONS PARENT, INC',
    juris: 'US-ME',
    from: '2024-04-14',
    to: '2024-04-14',
    notified: '2024-06-14',
    unit: 'individuals',
    count: 750_000,
  }),
  ag({
    source: 'tx-ag',
    id: 't4',
    c: 'ftr',
    name: 'Frontier Communications Parent, Inc. dba Frontier',
    juris: 'US-TX',
    from: '2024-04-14',
    to: '2024-04-14',
    notified: '2024-06-17',
    unit: 'state_residents',
    count: 90_000,
  }),

  // --- negatives ---
  // the same normalised name as a CIK company but 6 months after the 8-K: its own company and event
  small(
    'ca-ag',
    'c9',
    'The Clorox Company',
    'US-CA',
    '2024-03-01',
    '2024-03-05',
    1_200,
    'name:clorox:us-ca',
    'clorox-2024',
  ),
  // two unrelated small businesses with the same name in different states
  small(
    'ca-ag',
    'c10',
    'Pacific Coast Dental, LLC',
    'US-CA',
    '2024-05-01',
    '2024-05-03',
    3_000,
    'name:pacific-coast-dental:us-ca',
    'pcd-ca',
  ),
  small(
    'wa-ag',
    'w5',
    'Pacific Coast Dental Inc.',
    'US-WA',
    '2024-05-01',
    '2024-05-03',
    800,
    'name:pacific-coast-dental:us-wa',
    'pcd-wa',
  ),
  // one small company with two incidents months apart
  small(
    'wa-ag',
    'w6',
    'Lakeview Orthopedics PLLC',
    'US-WA',
    '2023-11-02',
    '2023-11-04',
    12_000,
    'name:lakeview-orthopedics:us-wa',
    'lakeview-1',
  ),
  small(
    'wa-ag',
    'w7',
    'LAKEVIEW ORTHOPEDICS',
    'US-WA',
    '2024-06-10',
    '2024-06-12',
    15_500,
    'name:lakeview-orthopedics:us-wa',
    'lakeview-2',
  ),
  // a domain: hint (a breach corpus keyed by site)
  {
    record: {
      source: 'hibp',
      noticeId: 'Ticketmaster',
      rawName: 'Ticketmaster',
      companyKey: 'domain:WWW.Ticketmaster.com',
      occurredFrom: '2024-04-02',
      occurredTo: '2024-05-28',
      notified: '2024-06-01',
      count: 560_000_000,
      countUnit: 'accounts',
    },
    expect: { companyKey: 'domain:ticketmaster.com', event: 'ticketmaster' },
  },
];
