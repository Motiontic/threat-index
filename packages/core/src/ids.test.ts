import { describe, expect, it } from 'vitest';
import { isCve, normaliseId, vulnKeyFor } from './ids';

describe('IDs', () => {
  it('normalises CVE and GHSA IDs', () => {
    expect(normaliseId(' cve-2025-3248 ')).toBe('CVE-2025-3248');
    expect(normaliseId('GHSA-C995-4FW3-J39M')).toBe('GHSA-c995-4fw3-j39m');
  });

  it('uses the CVE as the hub key when any alias has one', () => {
    expect(vulnKeyFor('GHSA-c995-4fw3-j39m', ['CVE-2025-3248'])).toBe('CVE-2025-3248');
    expect(vulnKeyFor('MAL-2025-1234')).toBe('MAL-2025-1234');
    expect(isCve('CVE-2021-44228')).toBe(true);
  });
});
