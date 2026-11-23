import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { FIXTURE_ENTRIES } from '../app/data/fixtures.server';

const byKey = new Map(FIXTURE_ENTRIES.map((e) => [e.key, e]));

describe('fixtures', () => {
  it('has about 15 records with unique keys', () => {
    expect(FIXTURE_ENTRIES.length).toBeGreaterThanOrEqual(15);
    expect(byKey.size).toBe(FIXTURE_ENTRIES.length);
  });

  it('keeps every summary in our own words, at most 300 characters', () => {
    for (const e of FIXTURE_ENTRIES) {
      expect(e.summary.length, e.key).toBeLessThanOrEqual(300);
      expect(e.summary.length, e.key).toBeGreaterThan(40);
    }
  });

  it('cites only sources that are on or ask', () => {
    for (const e of FIXTURE_ENTRIES) {
      expect(e.sources.length, e.key).toBeGreaterThan(0);
      for (const id of e.sources) {
        const source = SOURCE_BY_ID.get(id);
        expect(source, `${e.key} cites unknown source ${id}`).toBeDefined();
        expect(['on', 'ask'], `${e.key} cites ${id}`).toContain(source?.licence);
      }
    }
  });

  it('invents breach, AI and malicious-package records under EXAMPLE- and names only Example Co.', () => {
    const invented = FIXTURE_ENTRIES.filter((e) => ['breach', 'ai', 'mal'].includes(e.type));
    expect(invented.map((e) => e.type).sort()).toEqual(['ai', 'breach', 'breach', 'mal']);
    for (const e of invented) {
      expect(e.key.startsWith('EXAMPLE-'), e.key).toBe(true);
      const text = [e.title, e.subtitle, e.summary].join(' ');
      expect(text, e.key).toMatch(/Example Co\./);
      expect(text, e.key).toMatch(/example\.com|Example Co\./);
    }
    for (const e of FIXTURE_ENTRIES.filter((e) => !invented.includes(e))) {
      expect(e.key.startsWith('EXAMPLE-'), e.key).toBe(false);
    }
  });

  it.each([
    ['CVE-2025-3248', '2025-04-07', 9.8, '2025-05-05', ['GHSA-c995-4fw3-j39m']],
    ['CVE-2021-44228', '2021-12-10', 10, '2021-12-10', ['GHSA-jfh8-c2jp-5v3q']],
    ['CVE-2024-3094', '2024-03-29', 10, null, []],
    ['CVE-2023-34362', '2023-06-02', 9.8, '2023-06-02', []],
    ['CVE-2024-3400', '2024-04-12', 10, '2024-04-12', []],
    ['CVE-2024-6387', '2024-07-01', 8.1, null, []],
  ])('has the public facts for %s', (key, published, cvss, kev, aliases) => {
    expect(byKey.get(key)).toMatchObject({ type: 'vuln', published, cvss, kev_added: kev, aliases });
  });

  it('has the technique, weakness and term records', () => {
    for (const key of ['T1190', 'T1195.002', 'CWE-306']) expect(byKey.get(key)?.type).toBe('tech');
    for (const key of ['KEV', 'EPSS']) expect(byKey.get(key)?.type).toBe('term');
  });

  it('only gives CVSS and KEV dates to vulnerabilities', () => {
    for (const e of FIXTURE_ENTRIES.filter((e) => e.type !== 'vuln')) {
      expect(e.cvss, e.key).toBeNull();
      expect(e.kev_added, e.key).toBeNull();
    }
  });
});
