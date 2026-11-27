import { describe, expect, it } from 'vitest';
import { cvssDeliveredBy } from './cvss';

describe('cvssDeliveredBy', () => {
  it('prefers the recorded cvss_from', () => {
    expect(cvssDeliveredBy({ cvss_from: 'euvd', cvss_source: 'nvd' })).toBe('euvd');
  });
  it('derives nvd for NVD scores and cve-list for CNA/ADP names on old rows', () => {
    expect(cvssDeliveredBy({ cvss_from: null, cvss_source: 'nvd' })).toBe('nvd');
    expect(cvssDeliveredBy({ cvss_source: 'CISA-ADP', sources: '["cve-list"]' })).toBe('cve-list');
    expect(cvssDeliveredBy({ cvss_source: 'GitHub_M', sources: ['cisa-kev', 'cve-list'] })).toBe('cve-list');
  });
  it('is ambiguous (null) when euvd could have delivered it, or sources are unknown', () => {
    expect(cvssDeliveredBy({ cvss_source: 'GitHub_M', sources: '["enisa"]' })).toBeNull();
    expect(cvssDeliveredBy({ cvss_source: 'GitHub_M', sources: '["cve-list","enisa"]' })).toBeNull();
    expect(cvssDeliveredBy({ cvss_source: 'GitHub_M' })).toBeNull();
    expect(cvssDeliveredBy({ cvss_source: 'GitHub_M', sources: 'not json' })).toBeNull();
  });
  it('is null without a scorer', () => {
    expect(cvssDeliveredBy({ cvss_source: null })).toBeNull();
  });
});
