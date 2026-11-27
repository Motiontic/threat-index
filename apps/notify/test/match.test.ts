import { describe, expect, it } from 'vitest';
import { type EntityDoc, matchesSearch, matchOrder, parseTriggers } from '../src/match';

const doc = (o: Partial<EntityDoc> = {}): EntityDoc => ({
  type: 'vuln',
  key: 'CVE-2026-0001',
  title: 'Acme Gateway remote code execution',
  summary: 'Unauthenticated attackers can run code',
  cvss: 9.8,
  kevAdded: '2026-11-20',
  published: '2026-11-01',
  ...o,
});

describe('matchesSearch', () => {
  it('needs every term', () => {
    expect(matchesSearch({ query: 'acme gateway', params: {} }, doc())).toBe(true);
    expect(matchesSearch({ query: 'acme router', params: {} }, doc())).toBe(false);
  });
  it('matches the key and summary', () => {
    expect(matchesSearch({ query: 'cve-2026-0001', params: {} }, doc())).toBe(true);
    expect(matchesSearch({ query: 'unauthenticated', params: {} }, doc())).toBe(true);
  });
  it('an empty query with no filters matches nothing; with filters it matches by filter', () => {
    expect(matchesSearch({ query: '  ', params: {} }, doc())).toBe(false);
    expect(matchesSearch({ query: '', params: { type: [] } }, doc())).toBe(false);
    expect(matchesSearch({ query: '', params: { sev: ['critical'] } }, doc())).toBe(true);
  });
  it('uses the search route severity bands', () => {
    const q = (sev: string, cvss: number | null) =>
      matchesSearch({ query: 'acme', params: { sev: [sev] } }, doc({ cvss }));
    expect(q('critical', 9)).toBe(true);
    expect(q('high', 9)).toBe(false);
    expect(q('high', 7)).toBe(true);
    expect(q('medium', 4)).toBe(true);
    expect(q('low', 0)).toBe(false);
    expect(q('low', 3.9)).toBe(true);
    expect(q('critical', null)).toBe(false);
    expect(matchesSearch({ query: 'acme', params: { sev: ['low', 'critical'] } }, doc({ cvss: 9.5 }))).toBe(
      true,
    );
  });
  it('filters type, kev and year', () => {
    expect(matchesSearch({ query: 'acme', params: { type: ['breach'] } }, doc())).toBe(false);
    expect(matchesSearch({ query: 'acme', params: { type: ['vuln'] } }, doc())).toBe(true);
    expect(matchesSearch({ query: 'acme', params: { sig: ['kev'] } }, doc({ kevAdded: null }))).toBe(false);
    expect(matchesSearch({ query: 'acme', params: { sig: ['kev'] } }, doc())).toBe(true);
    expect(matchesSearch({ query: 'acme', params: { year: ['2025'] } }, doc())).toBe(false);
    expect(matchesSearch({ query: 'acme', params: { year: ['2025', '2026'] } }, doc())).toBe(true);
  });
  it('matches a company by key and name', () => {
    const c = doc({ type: 'breach', key: 'acme-corp', title: 'Acme Corp', summary: 'ignored words' });
    expect(matchesSearch({ query: 'acme corp', params: { type: ['breach'] } }, c)).toBe(true);
    expect(matchesSearch({ query: 'ignored', params: {} }, c)).toBe(false);
  });
});

describe('parseTriggers', () => {
  it('falls back to the five defaults on invalid JSON', () => {
    expect([...parseTriggers('nope')].sort()).toEqual(
      ['breach_notice', 'epss_band', 'fix_released', 'newly_exploited', 'public_exploit'].sort(),
    );
    expect(parseTriggers('["cvss_change"]').has('cvss_change')).toBe(true);
  });
});

describe('matchOrder', () => {
  const ch = (id: string, kind: string) => ({
    id,
    entity_key: id,
    kind,
    old: null,
    new: null,
    at: '2026-11-01T00:00:00Z',
    source: null,
  });
  it('keeps the first forward change first even behind many new_advisory changes', () => {
    const changes = [
      ch('first', 'kev_added'),
      ...Array.from({ length: 600 }, (_, i) => ch(`n${i}`, 'new_advisory')),
    ];
    const order = matchOrder(changes, changes.length);
    expect(order[0]?.id).toBe('first');
    expect(order[1]?.id).toBe('n0');
  });
  it('puts new_advisory first, forward before late, when the first change is itself leading', () => {
    const changes = [ch('a', 'kev_added'), ch('b', 'new_advisory'), ch('late', 'new_advisory')];
    expect(matchOrder(changes, 2).map((c) => c.id)).toEqual(['a', 'b', 'late']);
  });
  it('has no forced leader when there are no forward rows', () => {
    const changes = [ch('a', 'kev_added'), ch('b', 'new_advisory')];
    expect(matchOrder(changes, 0).map((c) => c.id)).toEqual(['b', 'a']);
  });
});
