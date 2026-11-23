import type { ParsedRecord } from '@ti/core/types';
import { expect, it } from 'vitest';
import { recordKind } from './kinds';
import { KEV_EXPLOITED } from './testing/fake-deps';

const samples: [string, ParsedRecord][] = [
  [
    'vuln',
    {
      key: 'CVE-2025-0001',
      kind: 'cve',
      title: 't',
      summary: '',
      modified: 'x',
      cwe: [],
      aliases: [],
      source: 's',
    },
  ],
  [
    'advisory',
    { source: 's', sourceId: 'GHSA-cfgh-jmpq-rvwx', vulnKey: null, status: 'active', modified: 'x' },
  ],
  ['signal', { vulnKey: 'CVE-2025-0001', kind: 'poc', source: 's', ref: 'r', firstSeen: '2025-01-01' }],
  ['notice', { source: 's', noticeId: 'n1', rawName: 'Acme', countUnit: 'claim' }],
  ['incident', { source: 's', incidentId: 'i1', kind: 'ai', title: 't' }],
  ['technique', { id: 'T1190', framework: 'attack', name: 'n' }],
];

it.each(samples)('classifies a %s record', (kind, record) => {
  expect(recordKind(record)).toBe(kind);
});

it('classifies the KEV signal as a signal, not a vuln or incident', () => {
  expect(recordKind(KEV_EXPLOITED)).toBe('signal');
});

it('throws, without record content, for an unknown object', () => {
  const secret = { hello: 'secret-value' } as unknown as ParsedRecord;
  expect(() => recordKind(secret)).toThrow('linker: unrecognised record');
  expect(() => recordKind(secret)).not.toThrow(/secret-value/);
  expect(() => recordKind(null as unknown as ParsedRecord)).toThrow('linker: unrecognised record');
});
