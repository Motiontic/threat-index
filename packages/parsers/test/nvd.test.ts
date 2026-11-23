import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { parseNvd } from '../src/nvd';

const resp = fixture('nvd', 'CVE-2024-3400.json');

describe('nvd parser', () => {
  it('takes the Primary score, skips the Secondary, drops NVD-CWE-* and keeps UTC dates', () => {
    const doc = JSON.parse(resp);
    const m = doc.vulnerabilities[0].cve.metrics.cvssMetricV31;
    // Make the two scores differ so the choice is visible.
    for (const e of m) e.cvssData.baseScore = e.type === 'Primary' ? 9.8 : 10;
    doc.vulnerabilities[0].cve.weaknesses.push({
      type: 'Primary',
      description: [
        { lang: 'en', value: 'NVD-CWE-Other' },
        { lang: 'en', value: 'NVD-CWE-noinfo' },
      ],
    });
    const { records } = parseNvd(doc);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      key: 'CVE-2024-3400',
      source: 'nvd',
      kind: 'cve',
      cvss: 9.8,
      cvssVersion: '3.1',
      cvssSource: 'nvd',
      cwe: ['CWE-20', 'CWE-77'],
      published: '2024-04-12T08:15:06.230Z',
      modified: '2026-06-17T07:44:11.533Z',
    });
  });

  it('skips a CVE whose only scores are Secondary', () => {
    const doc = JSON.parse(resp);
    doc.vulnerabilities[0].cve.metrics.cvssMetricV31 =
      doc.vulnerabilities[0].cve.metrics.cvssMetricV31.filter(
        (e: { type: string }) => e.type === 'Secondary',
      );
    expect(parseNvd(doc).records[0]).not.toHaveProperty('cvss');
    expect(parseNvd(doc).records[0]).not.toHaveProperty('cvssSource');
  });

  it('uses cisaVulnerabilityName as title, else the first sentence', () => {
    const doc = JSON.parse(resp);
    const cve = doc.vulnerabilities[0].cve;
    expect((parseNvd(doc).records[0] as unknown as { title: string }).title).toBe(cve.cisaVulnerabilityName);
    cve.cisaVulnerabilityName = undefined;
    expect((parseNvd(doc).records[0] as unknown as { title: string }).title).toMatch(
      /^A command injection as a result of/,
    );
  });

  it('accepts a single { cve } and a JSON string', () => {
    const cve = JSON.parse(resp).vulnerabilities[0];
    expect(parseNvd(cve).records).toHaveLength(1);
    expect(parseNvd(JSON.stringify(cve)).records).toHaveLength(1);
  });

  it('turns a rejected CVE into a rejected advisory and nothing else', () => {
    expect(parseNvd(fixture('nvd', 'rejected.json')).records).toEqual([
      {
        source: 'nvd',
        sourceId: 'CVE-2023-99001',
        vulnKey: 'CVE-2023-99001',
        status: 'rejected',
        published: '2023-06-01T08:15:00.000Z',
        modified: '2025-02-01T10:30:00.000Z',
      },
    ]);
  });

  it('handles a response with several entries', () => {
    const doc = JSON.parse(resp);
    const second = structuredClone(doc.vulnerabilities[0]);
    second.cve.id = 'cve-2024-0001';
    doc.vulnerabilities.push(second);
    const { records } = parseNvd(doc);
    expect(records.map((r) => (r as unknown as { key: string }).key)).toEqual([
      'CVE-2024-3400',
      'CVE-2024-0001',
    ]);
  });

  it('reports unknown cve fields and does not report known ones', () => {
    expect(parseNvd(resp).unknownFields).toEqual([]);
    const doc = JSON.parse(resp);
    doc.vulnerabilities[0].cve.brandNew = true;
    expect(parseNvd(doc).unknownFields).toEqual(['cve.brandNew']);
  });

  it('throws an error naming the parser for malformed input', () => {
    expect(() => parseNvd('nope')).toThrow(/^nvd: /);
    expect(() => parseNvd({ totalResults: 0 })).toThrow(/^nvd: /);
  });
});
