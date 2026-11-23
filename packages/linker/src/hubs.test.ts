import type { AdvisoryRecord, SignalRecord, VulnRecord } from '@ti/core/types';
import { expect, it } from 'vitest';
import { candidateIds, resolveHubs } from './hubs';

const vuln = (key: string, aliases: string[] = []): VulnRecord => ({
  key,
  kind: 'ghsa',
  title: 't',
  summary: '',
  modified: 'x',
  cwe: [],
  aliases,
  source: 's',
});
const adv = (sourceId: string, vulnKey: string | null = null): AdvisoryRecord => ({
  source: 's',
  sourceId,
  vulnKey,
  status: 'active',
  modified: 'x',
});
const sig = (vulnKey: string): SignalRecord => ({
  vulnKey,
  kind: 'poc',
  source: 's',
  ref: 'r',
  firstSeen: '2025-01-01',
});
const none = new Map<string, string>();
const noKeys = new Set<string>();

it('rule 1: the first CVE among the record IDs', () => {
  expect(
    resolveHubs([vuln('GHSA-cfgh-jmpq-rvwx', ['CVE-2025-0002', 'CVE-2025-0003'])], none, noKeys),
  ).toEqual(['CVE-2025-0002']);
  expect(resolveHubs([vuln('cve-2025-0009')], none, noKeys)).toEqual(['CVE-2025-0009']);
});

it('rule 2: another record in this call links the ID to a CVE (first wins)', () => {
  const hubs = resolveHubs(
    [
      sig('GHSA-cfgh-jmpq-rvwx'),
      vuln('CVE-2025-0001', ['GHSA-cfgh-jmpq-rvwx']),
      vuln('CVE-2025-0002', ['GHSA-cfgh-jmpq-rvwx']),
    ],
    none,
    noKeys,
  );
  expect(hubs).toEqual(['CVE-2025-0001', 'CVE-2025-0001', 'CVE-2025-0002']);
});

it('rule 3: a stored alias row', () => {
  const alias = new Map([['GHSA-cfgh-jmpq-rvwx', 'CVE-2025-0007']]);
  expect(resolveHubs([sig('GHSA-cfgh-jmpq-rvwx')], alias, noKeys)).toEqual(['CVE-2025-0007']);
});

it('rule 4: the smallest ID that has a stored vulns row', () => {
  const keys = new Set(['PYSEC-2', 'PYSEC-1']);
  expect(resolveHubs([vuln('GHSA-cfgh-jmpq-rvwx', ['PYSEC-2', 'PYSEC-1'])], none, keys)).toEqual(['PYSEC-1']);
});

it('rule 5: its own ID; a GHSA with no CVE resolves to itself', () => {
  expect(resolveHubs([adv('GHSA-CFGH-jmpq-rvwx')], none, noKeys)).toEqual(['GHSA-cfgh-jmpq-rvwx']);
});

it('a GHSA advisory with a CVE alias resolves to the CVE', () => {
  expect(resolveHubs([adv('GHSA-cfgh-jmpq-rvwx', 'CVE-2025-0005')], none, noKeys)).toEqual(['CVE-2025-0005']);
});

it('two CVEs never merge', () => {
  expect(
    resolveHubs([vuln('CVE-2025-0001', ['CVE-2025-0002']), vuln('CVE-2025-0002')], none, noKeys),
  ).toEqual(['CVE-2025-0001', 'CVE-2025-0002']);
});

it('unsafe IDs are dropped', () => {
  expect(candidateIds(vuln('../x'))).toBeNull();
  expect(candidateIds(vuln(''))).toBeNull();
  expect(candidateIds(vuln('CVE-2025-0001', ['../etc', 'GHSA-cfgh-jmpq-rvwx']))).toEqual([
    'CVE-2025-0001',
    'GHSA-cfgh-jmpq-rvwx',
  ]);
  expect(resolveHubs([vuln('../x'), sig('')], none, noKeys)).toEqual([null, null]);
});
