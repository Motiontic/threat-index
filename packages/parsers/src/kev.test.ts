import { describe, expect, it } from 'vitest';
import sample from '../../../fixtures/cisa-kev/sample.json';
import { parseKev } from './kev';

describe('CISA KEV parser', () => {
  it('turns each entry into an exploited-in-the-wild signal', () => {
    const out = parseKev(sample);
    expect(out.catalogVersion).toBe('2025.05.05');
    expect(out.records).toContainEqual(
      expect.objectContaining({ vulnKey: 'CVE-2025-3248', kind: 'exploited_wild', firstSeen: '2025-05-05' }),
    );
  });

  it('reports fields it does not know instead of failing', () => {
    const withNew = structuredClone(sample) as { vulnerabilities: Record<string, unknown>[] };
    const first = withNew.vulnerabilities[0];
    if (first) first.forensicTriage = 'example new field';
    expect(parseKev(withNew).unknownFields).toContain('forensicTriage');
  });
});
