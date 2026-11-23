import { expect, it } from 'vitest';
import { link } from './link';
import { BREACH_SET, type LabelledNotice } from './testing/breach-set';
import { makeFake } from './testing/fake-deps';

const when = (n: LabelledNotice): string =>
  n.record.notified ?? n.record.discovered ?? n.record.occurredFrom ?? '';

/** One batch per source, the source with the oldest notice first, as the collector would pull them. */
function batches(): LabelledNotice[][] {
  const bySource = new Map<string, LabelledNotice[]>();
  for (const n of BREACH_SET) bySource.set(n.record.source, [...(bySource.get(n.record.source) ?? []), n]);
  const oldest = (ns: LabelledNotice[]) => ns.map(when).sort()[0] as string;
  return [...bySource.values()].sort((a, b) => (oldest(a) < oldest(b) ? -1 : 1));
}

async function linkAll() {
  const f = makeFake();
  for (const batch of batches()) {
    const out = await link(
      batch.map((n) => n.record),
      f.deps,
    );
    f.apply(out.rows);
  }
  const stored = (n: LabelledNotice) =>
    f.tables.breach_notices.get(JSON.stringify([n.record.source, n.record.noticeId])) as Record<
      string,
      unknown
    >;
  return { f, stored };
}

it('the set is about 40 notices, with at most one labelled miss', () => {
  expect(BREACH_SET.length).toBeGreaterThanOrEqual(36);
  expect(BREACH_SET.length).toBeLessThanOrEqual(44);
  expect(BREACH_SET.filter((n) => n.expect.miss)).toHaveLength(1);
  expect(new Set(BREACH_SET.map((n) => `${n.record.source}/${n.record.noticeId}`)).size).toBe(
    BREACH_SET.length,
  );
});

it('(a) at least 95% of the notices labelled with a cik: key resolve to it', async () => {
  const { stored } = await linkAll();
  const labelled = BREACH_SET.filter((n) => n.expect.companyKey.startsWith('cik:'));
  const hits = labelled.filter((n) => stored(n).company_key === n.expect.companyKey);
  const misses = labelled.filter((n) => stored(n).company_key !== n.expect.companyKey);
  const rate = hits.length / labelled.length;
  console.log(
    `CIK match rate: ${hits.length}/${labelled.length} = ${(rate * 100).toFixed(1)}%; misses: ${misses
      .map((n) => `${n.record.source}/${n.record.noticeId} (${n.record.rawName}) -> ${stored(n).company_key}`)
      .join(', ')}`,
  );
  expect(rate).toBeGreaterThanOrEqual(0.95);
  expect(misses.every((n) => n.expect.miss)).toBe(true); // only the labelled miss may fail
});

it('(b) no notice resolves to a cik: key other than its label', async () => {
  const { stored } = await linkAll();
  for (const n of BREACH_SET) {
    const got = String(stored(n).company_key);
    if (got.startsWith('cik:'))
      expect(got, `${n.record.source}/${n.record.noticeId}`).toBe(n.expect.companyKey);
  }
});

it('every non-cik label resolves to exactly its name: or domain: key', async () => {
  const { stored } = await linkAll();
  for (const n of BREACH_SET.filter((x) => !x.expect.companyKey.startsWith('cik:')))
    expect(stored(n).company_key, `${n.record.source}/${n.record.noticeId}`).toBe(n.expect.companyKey);
});

it('(c) events match the labelled groups', async () => {
  const { f, stored } = await linkAll();
  const byLabel = new Map<string, Set<string>>();
  const byKey = new Map<string, Set<string>>();
  for (const n of BREACH_SET.filter((x) => !x.expect.miss)) {
    const ev = String(stored(n).event_key);
    byLabel.set(n.expect.event, (byLabel.get(n.expect.event) ?? new Set()).add(ev));
    byKey.set(ev, (byKey.get(ev) ?? new Set()).add(n.expect.event));
    expect(f.tables.breach_events.has(JSON.stringify([ev])), ev).toBe(true);
  }
  for (const [label, keys] of byLabel) expect([...keys], `${label} is one event`).toHaveLength(1);
  for (const [key, labels] of byKey) expect([...labels], `${key} holds one group`).toHaveLength(1);
  // the miss is in an event of its own company, never in the 23andMe event
  const miss = BREACH_SET.find((n) => n.expect.miss) as LabelledNotice;
  expect(stored(miss).event_key).not.toBe(stored(BREACH_SET[3] as LabelledNotice).event_key);
  // notice counts per event equal the labelled group sizes
  for (const [label] of byLabel) {
    const group = BREACH_SET.filter((n) => n.expect.event === label && !n.expect.miss);
    const ev = f.tables.breach_events.get(JSON.stringify([stored(group[0] as LabelledNotice).event_key]));
    expect(ev?.notice_count, label).toBe(group.length);
  }
});

it('(d) every counts_by_unit holds the source counts unchanged, by unit and jurisdiction, with no sum', async () => {
  const { f, stored } = await linkAll();
  const labels = new Set(BREACH_SET.filter((n) => !n.expect.miss).map((n) => n.expect.event));
  for (const label of labels) {
    const group = BREACH_SET.filter((n) => n.expect.event === label && !n.expect.miss);
    const ev = f.tables.breach_events.get(JSON.stringify([stored(group[0] as LabelledNotice).event_key]));
    const counts = JSON.parse(String(ev?.counts_by_unit)) as Record<string, Record<string, number>>;
    const source = new Map<string, number[]>();
    for (const n of group) {
      if (n.record.count == null) continue;
      const k = `${n.record.countUnit}|${n.record.jurisdiction ?? '-'}`;
      source.set(k, [...(source.get(k) ?? []), n.record.count]);
    }
    const got = Object.entries(counts).flatMap(([unit, byJ]) =>
      Object.entries(byJ).map(([j, v]) => [`${unit}|${j}`, v] as const),
    );
    expect(got.map(([k]) => k).sort(), label).toEqual([...source.keys()].sort());
    for (const [k, v] of got) expect(source.get(k), `${label} ${k}`).toContain(v); // a source count, not a sum
    expect(Object.keys(ev as object)).not.toContain('total');
  }
});
