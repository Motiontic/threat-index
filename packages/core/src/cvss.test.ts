import { describe, expect, it } from 'vitest';
import { cvssDeliveredBy } from './cvss';

describe('cvssDeliveredBy', () => {
  it('prefers the recorded cvss_from', () => {
    expect(cvssDeliveredBy({ cvss_from: 'euvd', cvss_source: 'nvd' })).toBe('euvd');
  });
  it('derives nvd for NVD scores and cve-list for CNA/ADP names on old rows', () => {
    expect(cvssDeliveredBy({ cvss_from: null, cvss_source: 'nvd' })).toBe('nvd');
    expect(cvssDeliveredBy({ cvss_source: 'CISA-ADP' })).toBe('cve-list');
    expect(cvssDeliveredBy({ cvss_source: 'GitHub_M' })).toBe('cve-list');
  });
  it('is null without a scorer', () => {
    expect(cvssDeliveredBy({ cvss_source: null })).toBeNull();
  });
});
