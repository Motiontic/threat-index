import { describe, expect, it } from 'vitest';
import { cvssCandidates, cvssShown } from './cvss';

const all = () => true;
const hide =
  (...ids: string[]) =>
  (id: string) =>
    !ids.includes(id);

describe('cvssCandidates', () => {
  it('uses the recorded cvss_from alone', () => {
    expect(cvssCandidates({ cvss_from: 'enisa', cvss_source: 'nvd' })).toEqual(['enisa']);
  });
  it('derives nvd for NVD scores on old rows', () => {
    expect(cvssCandidates({ cvss_from: null, cvss_source: 'nvd', sources: '["cve-list","enisa"]' })).toEqual([
      'nvd',
    ]);
  });
  it('lists every score-carrying source the old row names', () => {
    expect(cvssCandidates({ cvss_source: 'CISA-ADP', sources: '["cve-list"]' })).toEqual(['cve-list']);
    expect(cvssCandidates({ cvss_source: 'GitHub_M', sources: ['cisa-kev', 'cve-list', 'enisa'] })).toEqual([
      'cve-list',
      'enisa',
    ]);
    expect(cvssCandidates({ cvss_source: 'GitHub_M', sources: '["nvd","cve-list"]' })).toEqual([
      'cve-list',
      'nvd',
    ]);
  });
  it('is empty without a scorer or without any score-carrying source', () => {
    expect(cvssCandidates({ cvss_source: null, sources: '["cve-list"]' })).toEqual([]);
    expect(cvssCandidates({ cvss_source: 'GitHub_M' })).toEqual([]);
    expect(cvssCandidates({ cvss_source: 'GitHub_M', sources: 'not json' })).toEqual([]);
    expect(cvssCandidates({ cvss_source: 'GitHub_M', sources: '["cisa-kev"]' })).toEqual([]);
  });
});

describe('cvssShown', () => {
  it('shows a Log4Shell-shaped old row (CNA score, listed by cve-list and enisa) when both are visible', () => {
    expect(cvssShown({ cvss_source: 'apache', sources: '["cve-list","enisa","cisa-kev"]' }, all)).toBe(true);
  });
  it('hides an ambiguous old row when any candidate is hidden', () => {
    expect(cvssShown({ cvss_source: 'apache', sources: '["cve-list","enisa"]' }, hide('enisa'))).toBe(false);
    expect(cvssShown({ cvss_source: 'apache', sources: '["cve-list","enisa"]' }, hide('cve-list'))).toBe(
      false,
    );
  });
  it('follows cvss_from exactly on new rows', () => {
    expect(
      cvssShown({ cvss_from: 'cve-list', cvss_source: 'apache', sources: '["enisa"]' }, hide('enisa')),
    ).toBe(true);
    expect(cvssShown({ cvss_from: 'enisa', cvss_source: 'apache' }, hide('enisa'))).toBe(false);
  });
  it('hides when there is no candidate', () => {
    expect(cvssShown({ cvss_source: 'apache', sources: '["cisa-kev"]' }, all)).toBe(false);
  });
});
