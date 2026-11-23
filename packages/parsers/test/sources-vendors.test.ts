import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { loadParser } from '../src/load';

interface GlobImportMeta {
  glob(pattern: string, options: { query: string; import: string; eager: true }): Record<string, string>;
}
const sources = (import.meta as unknown as GlobImportMeta).glob('../src/*.ts', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const src = (id: string) => {
  const s = SOURCE_BY_ID.get(id);
  if (!s) throw new Error(`no source ${id}`);
  return s;
};

const WIRED = {
  'red-hat': {
    licence: 'on',
    credit: 'Source: Red Hat Security Data (CC BY 4.0)',
    changelist: {
      listUrl: 'https://security.access.redhat.com/data/csaf/v2/vex/changes.csv',
      timeColumn: 1,
      refColumn: 0,
      itemUrl: 'https://security.access.redhat.com/data/csaf/v2/vex/{ref}',
      rangeBytes: 262_144,
    },
  },
  msrc: {
    licence: 'ask',
    credit: 'Source: Microsoft MSRC',
    rateLimit: { perMinute: 60 },
    changelist: {
      listUrl: 'https://msrc.microsoft.com/csaf/advisories/changes.csv',
      timeColumn: 1,
      refColumn: 0,
      itemUrl: 'https://msrc.microsoft.com/csaf/advisories/{ref}',
    },
  },
  cisco: {
    licence: 'ask',
    credit: 'Source: Cisco',
    changelist: {
      listUrl: 'https://www.cisco.com/.well-known/csaf/changes.csv',
      timeColumn: 1,
      refColumn: 0,
      itemUrl: 'https://www.cisco.com/.well-known/csaf/{ref}',
      rangeBytes: 262_144,
    },
  },
} as const;

describe('the vendor sources', () => {
  for (const [id, want] of Object.entries(WIRED)) {
    it(`${id}: csaf parser loads; pull, rateLimit, licence, credit match`, async () => {
      const s = src(id);
      expect(s.parser).toBe('csaf');
      expect(s.pattern).toBe('changelist');
      expect(s.licence).toBe(want.licence);
      expect(s.credit).toBe(want.credit);
      expect(s.pull).toEqual({ changelist: want.changelist });
      expect(s.rateLimit).toEqual('rateLimit' in want ? want.rateLimit : undefined);
      expect(typeof (await loadParser('csaf')).parse).toBe('function');
    });
  }

  it('oracle has no parser and no pull; licence and credit unchanged', () => {
    const s = src('oracle');
    expect(s.parser).toBeUndefined();
    expect(s.pull).toBeUndefined();
    expect(s.licence).toBe('ask');
    expect(s.credit).toBe('Source: Oracle');
  });

  it('csaf.ts is Worker-safe', () => {
    const text = sources['../src/csaf.ts'] ?? '';
    expect(text.length).toBeGreaterThan(0);
    expect(text).not.toMatch(/node:|Buffer|process\.|require\(/);
  });
});
