import { describe, expect, it } from 'vitest';
import {
  indexLetterKey,
  jobPrefix,
  lakeKey,
  lookupVulnKey,
  rawReceiptKey,
  sitemapKey,
  vulnDocKey,
  vulnShard,
} from './r2-keys';

describe('R2 keys', () => {
  it('rawReceiptKey uses the UTC date', () => {
    expect(rawReceiptKey('kev', 'run1', 2, new Date('2026-03-04T23:59:59Z'))).toBe(
      'raw/kev/2026/03/04/run1-2.ndjson.gz',
    );
    expect(rawReceiptKey('kev', 'run1', 0, new Date('2026-12-31T23:30:00-05:00'))).toBe(
      'raw/kev/2027/01/01/run1-0.ndjson.gz',
    );
  });
  it('jobPrefix and vulnDocKey', () => {
    expect(jobPrefix('j1')).toBe('jobs/j1/');
    expect(vulnDocKey('CVE-2024-3094')).toBe('docs/vuln/CVE-2024-3094.json');
  });
  it('vulnShard matches fixed FNV-1a values (computed independently)', () => {
    expect(vulnShard('CVE-2024-3094')).toBe('e1f');
    expect(vulnShard('CVE-2021-44228')).toBe('7dc');
    expect(vulnShard('GHSA-c995-4fw3-j39m')).toBe('478');
  });
  it('vulnShard normalises the key and always gives three hex digits', () => {
    expect(vulnShard(' cve-2021-44228 ')).toBe('7dc');
    expect(vulnShard('GHSA-C995-4FW3-J39M')).toBe('478');
    for (const k of ['a', 'b', 'OSV-1', 'MAL-2024-1']) expect(vulnShard(k)).toMatch(/^[0-9a-f]{3}$/);
  });
  it('lookupVulnKey', () => {
    expect(lookupVulnKey('CVE-2021-44228')).toBe('lookup/vuln/7dc.json');
  });
});

describe('seam R2 keys', () => {
  it('indexLetterKey', () => {
    expect(indexLetterKey('a')).toBe('lookup/index/a.json');
    expect(indexLetterKey('0')).toBe('lookup/index/0.json');
  });
  it('lakeKey', () => {
    expect(lakeKey('vulns', 'nvd', 2025, 3)).toBe('lake/vulns/nvd/2025/part-3.parquet');
  });
  it('sitemapKey', () => {
    expect(sitemapKey()).toBe('sitemap.xml');
  });
});
