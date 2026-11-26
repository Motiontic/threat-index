import type { Comparer } from '@ti/core/versions';
import { inRange } from '@ti/core/versions';
import { describe, expect, it } from 'vitest';
import type { AffectedRecordRow } from '../src/lib/packages-lookup';
import { fixedInFor, NOTE, pickUpgrade, rowCovers, type VersionRules } from '../src/lib/packages-match';
import { secondsToUtcMidnight } from '../src/lib/packages-quota';

/** A toy comparer: versions are non-negative integers. */
const toy: Comparer = { valid: (v) => /^\d+$/.test(v), compare: (a, b) => Number(a) - Number(b) };
const withToy: VersionRules = { inRange, comparerFor: () => toy };
const noComparer: VersionRules = { inRange, comparerFor: () => null };

const row = (o: Partial<AffectedRecordRow> = {}): AffectedRecordRow => ({
  ecosystem: 'Maven',
  name: 'x',
  source: 'github-advisory-db',
  source_id: 'GHSA-1',
  range_no: 0,
  vuln_key: 'CVE-2099-1',
  range_type: 'SEMVER',
  introduced: '0',
  fixed: '5',
  last_affected: null,
  versions: null,
  summary: null,
  severity: null,
  reviewed: 1,
  url: null,
  published: null,
  modified: '2026-01-02T00:00:00Z',
  ...o,
});

describe('rowCovers', () => {
  it('an all-versions range covers any version with no comparer', () => {
    const r = row({ fixed: null });
    expect(rowCovers('npm', 'anything', r, noComparer)).toBe(true);
    expect(rowCovers('npm', '1.0.0', r)).toBe(true);
  });
  it('an EXACT row goes to inRange', () => {
    const r = row({ range_type: 'EXACT', versions: '["1.0.0"]', fixed: null });
    expect(rowCovers('npm', '1.0.0', r)).toBe(true);
    expect(rowCovers('npm', '2.0.0', r)).toBe(false);
  });
  it('any other range is unsupported without a comparer', () => {
    expect(rowCovers('npm', '1.0.0', row())).toBe('unsupported');
    expect(rowCovers('npm', '1.0.0', row({ introduced: '2', fixed: null }))).toBe('unsupported');
  });
  it('uses the comparer when there is one', () => {
    expect(rowCovers('npm', '3', row(), withToy)).toBe(true);
    expect(rowCovers('npm', '5', row(), withToy)).toBe(false);
  });
});

describe('fixedInFor', () => {
  it('reads only reviewed rows with a well-formed fix above the version', () => {
    expect(fixedInFor('Maven', '3', [row()], withToy)?.value).toBe('5');
    expect(fixedInFor('Maven', '3', [row({ reviewed: 0, fixed: '9' })], withToy)).toBeNull();
    expect(fixedInFor('Maven', '3', [row({ fixed: 'other-pkg@1.0' })], withToy)).toBeNull();
    expect(fixedInFor('Maven', '3', [row({ fixed: '2' })], withToy)).toBeNull();
  });
  it('picks the highest of several, or nothing without a comparer', () => {
    const rows = [row({ fixed: '5' }), row({ source_id: 'B', fixed: '7' })];
    expect(fixedInFor('Maven', '3', rows, withToy)?.value).toBe('7');
    expect(
      fixedInFor('Maven', '1.0.0', [row({ fixed: '1.1.0' }), row({ fixed: '1.2.0' })], noComparer),
    ).toBeNull();
    expect(fixedInFor('Maven', '1.0.0', [row({ fixed: '1.1.0' })], noComparer)?.value).toBe('1.1.0');
  });
});

describe('pickUpgrade', () => {
  const rec = { source: 'github-advisory-db', source_id: 'GHSA-1', modified: '2026-01-02T00:00:00Z' };
  const m = (id: string, value: string | null, malicious = false) => ({
    id,
    malicious,
    fix: value === null ? null : { value, record: rec },
  });
  const ok = (rows: AffectedRecordRow[], matches = [m('A', '5')], rules = withToy) =>
    pickUpgrade('Maven', '3', matches, rows, rules);

  it('suggests a clear candidate, with the source name, id and date', () => {
    expect(ok([row()])).toEqual({
      upgradeTo: '5',
      upgradeNote: NOTE.suggestion('5', 'GitHub Advisory DB', 'GHSA-1', '2026-01-02'),
    });
    expect(NOTE.suggestion('5', 'S', 'ID', '2026-01-02')).toContain(
      "Confirm 5 exists in the registry and isn't brand new",
    );
  });
  it('no fix → null with the right note, malicious first', () => {
    expect(ok([row()], [m('A', '5'), m('B', null)])).toEqual({
      upgradeTo: null,
      upgradeNote: NOTE.noFix('B'),
    });
    expect(ok([row()], [m('B', null), m('MAL-1', null, true)])).toEqual({
      upgradeTo: null,
      upgradeNote: NOTE.malicious('MAL-1'),
    });
  });
  it('the candidate itself affected → null', () => {
    const exact = row({ range_type: 'EXACT', versions: '["5"]', fixed: null, source_id: 'M' });
    expect(ok([row(), exact]).upgradeNote).toBe(NOTE.candidateAffected('5'));
    const second = row({ source_id: 'S', introduced: '5', fixed: '7' });
    expect(ok([row(), second])).toEqual({ upgradeTo: null, upgradeNote: NOTE.candidateAffected('5') });
  });
  it("a candidate that can't be checked → null", () => {
    const unsupported: VersionRules = {
      comparerFor: () => toy,
      inRange: (_e, v, r) => (v === '5' && r.introduced === '9' ? 'unsupported' : v < '5'),
    };
    expect(ok([row(), row({ source_id: 'U', introduced: '9' })], [m('A', '5')], unsupported)).toEqual({
      upgradeTo: null,
      upgradeNote: NOTE.cantCheck('5', 'Maven'),
    });
  });
  it('picks the highest fix, and refuses to order without a comparer', () => {
    const rows = [row({ fixed: '5' }), row({ source_id: 'B', vuln_key: 'CVE-2099-2', fixed: '7' })];
    expect(ok(rows, [m('A', '5'), m('B', '7')]).upgradeTo).toBe('7');
    expect(ok(rows, [m('A', '5'), m('B', '7')], noComparer)).toEqual({
      upgradeTo: null,
      upgradeNote: NOTE.cantOrder('Maven'),
    });
  });
  it('no matches → nothing to say', () => {
    expect(ok([], [])).toEqual({ upgradeTo: null, upgradeNote: null });
  });
});

describe('note templates', () => {
  it('have fixed wording', () => {
    expect(NOTE.noFix('X')).toBe('No reviewed fix is listed for X.');
    expect(NOTE.malicious('X')).toBe(
      'X marks this package as malicious. Remove it rather than upgrading, and treat machines that installed it as exposed.',
    );
    expect(NOTE.candidateAffected('1')).toBe('1 is listed as affected too, so no upgrade is suggested.');
    expect(NOTE.cantCheck('1', 'npm')).toBe(
      "MTI can't yet check 1 against every listed range for npm, so no upgrade is suggested.",
    );
    expect(NOTE.cantOrder('Maven')).toBe(
      "MTI can't yet order Maven versions, so it can't pick one version that fixes every match.",
    );
  });
});

describe('secondsToUtcMidnight', () => {
  it('counts to the next 00:00 UTC, at least 1', () => {
    expect(secondsToUtcMidnight(new Date('2026-11-26T00:00:00Z'))).toBe(86_400);
    expect(secondsToUtcMidnight(new Date('2026-11-26T23:59:59.5Z'))).toBe(1);
    expect(secondsToUtcMidnight(new Date('2026-11-26T23:59:30Z'))).toBe(30);
  });
});
