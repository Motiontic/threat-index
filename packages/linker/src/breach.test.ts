import type { NoticeRecord } from '@ti/core/types';
import { expect, it } from 'vitest';
import { assignEvents, eventRow, type LinkedNotice } from './breach';
import { link } from './link';
import { makeFake } from './testing/fake-deps';

const SEC: NoticeRecord = {
  source: 'sec-8k',
  noticeId: 'sec1',
  rawName: 'Acme Corp.',
  companyKey: 'cik:1234',
  discovered: '2024-05-01',
  countUnit: 'not_stated',
};
const CA: NoticeRecord = {
  source: 'ca-ag',
  noticeId: 'ca1',
  rawName: 'The ACME Corporation',
  jurisdiction: 'US-CA',
  occurredFrom: '2024-04-20',
  occurredTo: '2024-05-10',
  notified: '2024-07-01',
  count: 100,
  countUnit: 'state_residents',
};

const rows = (out: Awaited<ReturnType<typeof link>>, table: string) =>
  out.rows.filter((r) => r.table === table).map((r) => r.row);

async function run(records: NoticeRecord[], f = makeFake()) {
  const out = await link(records, f.deps);
  f.apply(out.rows);
  return { out, f };
}

it('a name matches an earlier CIK notice stored by another run, within 30 days', async () => {
  const { f } = await run([SEC]);
  const { out } = await run([CA], f);
  expect(rows(out, 'breach_notices')[0]).toMatchObject({
    company_key: 'cik:0000001234',
    event_key: 'cik:0000001234@2024-05-01',
    name_key: 'acme',
  });
  expect(rows(out, 'breach_events')[0]).toMatchObject({
    key: 'cik:0000001234@2024-05-01',
    notice_count: 2,
    confidence: 0.8,
    first_seen: '2024-07-01',
    dates: '{"from":"2024-04-20","to":"2024-05-10"}',
  });
  expect(rows(out, 'companies')).toEqual([]); // alias 'acme' is already stored
  expect(out.rows.filter((r) => r.table === 'changes').map((r) => r.row)).toMatchObject([
    { entity_key: 'cik:0000001234', new: 'ca-ag:ca1' },
  ]);
});

it('a name without dates never joins by name; one 31+ days away gets its own company and event', async () => {
  const { f } = await run([SEC]);
  const { out } = await run(
    [
      { ...CA, noticeId: 'nodate', occurredFrom: undefined, occurredTo: undefined, notified: undefined },
      { ...CA, noticeId: 'late', occurredFrom: '2024-07-01', occurredTo: '2024-07-02' },
    ],
    f,
  );
  const n = rows(out, 'breach_notices');
  expect(n.map((r) => r.company_key)).toEqual(['name:acme:us-ca', 'name:acme:us-ca']);
  expect(n[0]?.event_key).toBe('name:acme:us-ca@ca-ag:nodate');
  expect(n[1]?.event_key).toBe('name:acme:us-ca@2024-07-01');
});

it('joins the same company in the same batch and groups by 30-day closeness', async () => {
  const { out } = await run([
    { ...CA, noticeId: 'a', occurredFrom: '2024-01-01', occurredTo: '2024-01-01' },
    { ...CA, noticeId: 'b', occurredFrom: '2024-01-25', occurredTo: '2024-01-25' },
    { ...CA, noticeId: 'c', occurredFrom: '2024-06-01', occurredTo: '2024-06-01' },
  ]);
  const n = rows(out, 'breach_notices');
  expect(n.map((r) => r.event_key)).toEqual([
    'name:acme:us-ca@2024-01-01',
    'name:acme:us-ca@2024-01-01',
    'name:acme:us-ca@2024-06-01',
  ]);
  expect(rows(out, 'breach_events').map((r) => [r.key, r.notice_count])).toEqual([
    ['name:acme:us-ca@2024-01-01', 2],
    ['name:acme:us-ca@2024-06-01', 1],
  ]);
  // the same name in another state is another company
  const wa = await run([{ ...CA, noticeId: 'z', jurisdiction: 'US-WA' }]);
  expect(rows(wa.out, 'breach_notices')[0]?.company_key).toBe('name:acme:us-wa');
});

function linkedNotice(over: Partial<LinkedNotice> & { r: NoticeRecord }): LinkedNotice {
  return { idx: 0, companyKey: 'c', nameKey: 'c', confidence: 0.6, eventKey: null, ...over };
}

it('a key taken by an event that is not close gets -2, -3', () => {
  // two stored events of company c, whose keys are older than their notices' dates
  const prior = [
    {
      source: 's',
      notice_id: '1',
      company_key: 'c',
      event_key: 'c@2024-01-01',
      occurred_from: '2023-01-01',
      occurred_to: '2023-01-01',
    },
    {
      source: 's',
      notice_id: '2',
      company_key: 'c',
      event_key: 'c@2024-01-01-2',
      occurred_from: '2023-06-01',
      occurred_to: '2023-06-01',
    },
  ];
  const l = linkedNotice({
    r: { source: 's', noticeId: '3', rawName: 'c', countUnit: 'claim', occurredFrom: '2024-01-01' },
  });
  assignEvents([l], prior);
  expect(l.eventKey).toBe('c@2024-01-01-3');
});

it('with several candidates a notice joins the one whose earliest notice is earliest; events are not merged', () => {
  const prior = [
    {
      source: 's',
      notice_id: '1',
      company_key: 'c',
      event_key: 'late',
      occurred_from: '2024-03-01',
      occurred_to: '2024-03-01',
    },
    {
      source: 's',
      notice_id: '2',
      company_key: 'c',
      event_key: 'early',
      occurred_from: '2024-01-20',
      occurred_to: '2024-01-20',
    },
  ];
  const l = linkedNotice({
    r: { source: 's', noticeId: '3', rawName: 'c', countUnit: 'claim', occurredFrom: '2024-02-15' },
  });
  assignEvents([l], prior);
  expect(l.eventKey).toBe('early');
});

it('event keys without dates stay under 200 characters', () => {
  const l = linkedNotice({
    companyKey: `name:${'a'.repeat(100)}:us-ca`,
    r: { source: 's'.repeat(100), noticeId: 'n'.repeat(300), rawName: 'x', countUnit: 'claim' },
  });
  const l2 = linkedNotice({ ...l, r: { ...l.r, noticeId: 'n'.repeat(301) } });
  assignEvents([l, l2], []);
  expect(l.eventKey?.length).toBeLessThan(200);
  expect(l2.eventKey?.length).toBeLessThan(200);
  expect(l2.eventKey).not.toBe(l.eventKey);
});

it('counts stay under their own unit and jurisdiction; no total anywhere', async () => {
  const base = { occurredFrom: '2024-05-01', occurredTo: '2024-05-02' };
  const { out } = await run([
    { ...SEC, count: undefined },
    { ...CA, ...base, noticeId: 'i1', jurisdiction: 'US-CA', count: 1000, countUnit: 'individuals' },
    { ...CA, ...base, noticeId: 'ca', jurisdiction: 'US-CA', count: 300, countUnit: 'state_residents' },
    { ...CA, ...base, noticeId: 'ca-again', jurisdiction: 'US-CA', count: 350, countUnit: 'state_residents' },
    { ...CA, ...base, noticeId: 'wa', jurisdiction: 'US-WA', count: 200, countUnit: 'state_residents' },
    { ...CA, ...base, noticeId: 'ns', jurisdiction: 'US-TX', count: undefined, countUnit: 'not_stated' },
  ]);
  const [event] = rows(out, 'breach_events');
  expect(event?.notice_count).toBe(6);
  expect(JSON.parse(event?.counts_by_unit as string)).toEqual({
    individuals: { 'US-CA': 1000 },
    state_residents: { 'US-CA': 350, 'US-WA': 200 },
  });
  expect(Object.keys(event as object).sort()).toEqual([
    'company_key',
    'confidence',
    'counts_by_unit',
    'dates',
    'first_seen',
    'key',
    'modified',
    'notice_count',
  ]);
  // 1000 + 350 + 200 (or any other sum) never appears
  expect(String(event?.counts_by_unit).match(/\d+/g)?.sort()).toEqual(['1000', '200', '350']);
});

it('rebuilds an event from stored notices, never incrementally', async () => {
  const { f } = await run([SEC, CA]);
  const stored = f.all('breach_events')[0] as Record<string, unknown>;
  expect(stored.notice_count).toBe(2);
  // a corrupted stored event is repaired by the next notice that touches it
  f.put('breach_events', {
    ...stored,
    notice_count: 99,
    counts_by_unit: '{"state_residents":{"US-CA":9999}}',
  });
  const { out } = await run([{ ...CA, noticeId: 'ca2', jurisdiction: 'US-WA', count: 5 }], f);
  expect(rows(out, 'breach_events')[0]).toMatchObject({ notice_count: 3 });
  expect(JSON.parse(rows(out, 'breach_events')[0]?.counts_by_unit as string)).toEqual({
    state_residents: { 'US-CA': 100, 'US-WA': 5 },
  });
});

it('a stored notice is never re-matched', async () => {
  const f = makeFake();
  // stored before the SEC notice was known: matched by name
  await run([{ ...CA, noticeId: 'old', occurredFrom: '2024-05-01' }], f);
  await run([SEC], f);
  const { out } = await run([{ ...CA, noticeId: 'old', occurredFrom: '2024-05-01' }], f);
  expect(out.rows).toEqual([]);
  expect(f.tables.breach_notices.get(JSON.stringify(['ca-ag', 'old']))).toMatchObject({
    company_key: 'name:acme:us-ca',
  });
});

it('rerunning the same batch emits no rows', async () => {
  const batch: NoticeRecord[] = [
    SEC,
    CA,
    { ...CA, noticeId: 'wa', jurisdiction: 'US-WA', count: 7 },
    {
      source: 'hibp',
      noticeId: 'h',
      rawName: 'Foo',
      companyKey: 'domain:WWW.foo.com',
      countUnit: 'accounts',
      count: 3,
    },
    { source: 'hibp', noticeId: 'x', rawName: '!!!', countUnit: 'accounts' },
  ];
  const { out, f } = await run(batch);
  expect(out.rows.filter((r) => r.table === 'changes')).toHaveLength(4); // the notice with no name has none
  expect(rows(out, 'breach_notices').find((r) => r.notice_id === 'x')).toMatchObject({
    company_key: null,
    event_key: null,
  });
  expect(rows(out, 'companies').map((r) => r.key)).toEqual(['cik:0000001234', 'domain:foo.com']);
  expect((await link(batch, f.deps)).rows).toEqual([]);
});

it('backfills name_key on a stored notice without touching its company or event', async () => {
  const { f } = await run([CA]);
  const key = JSON.stringify(['ca-ag', 'ca1']);
  const row = f.tables.breach_notices.get(key) as Record<string, unknown>;
  f.put('breach_notices', { ...row, name_key: null });
  const out = await link([CA], f.deps);
  expect(out.rows.map((r) => r.table)).toEqual(['breach_notices']);
  expect(out.rows[0]?.row).toMatchObject({
    name_key: 'acme',
    company_key: row.company_key,
    event_key: row.event_key,
  });
});

it('eventRow is null when only modified would change', async () => {
  const { f } = await run([CA]);
  const ev = f.all('breach_events')[0] as Record<string, unknown>;
  const notices = f.all('breach_notices');
  expect(eventRow(ev.key as string, notices, ev, '2027-01-01T00:00:00.000Z')).toBeNull();
});
