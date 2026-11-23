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
  avid: {
    parser: 'avid',
    pattern: 'git',
    licence: 'on',
    credit: 'Source: AVID',
    pull: {
      git: {
        repo: 'avidml/avid-db',
        branch: 'main',
        include: ['reports/20*/AVID-*.json', 'vulnerabilities/20*/AVID-*.json'],
      },
    },
  },
  aiaaic: {
    parser: 'aiaaic',
    pattern: 'fingerprint',
    licence: 'ask',
    credit: 'Source: AIAAIC',
    pull: {
      fingerprint: {
        url: 'https://docs.google.com/spreadsheets/d/1Bn55B4xz21-_Rgdr8BBb2lt0n_4rzLGxFADMlVW0PYI/export?format=csv&gid=888071280&range=A2:T',
        format: 'csv',
        key: 'AIAAIC ID#',
      },
    },
  },
  'cfr-tracker': {
    parser: 'cfr-cyber-ops',
    pattern: 'fingerprint',
    licence: 'ask',
    credit: 'Source: CFR Cyber Operations Tracker',
    pull: {
      fingerprint: {
        url: 'https://static.cfr.org/cyber-operations/data/cyber-operations-incidents.csv',
        format: 'csv',
        key: 'Title',
      },
    },
  },
} as const;

const UNWIRED = {
  'mit-ai-risk': { licence: 'on', credit: 'Source: MIT AI Risk Repository' },
  csis: { licence: 'ask', credit: 'Source: CSIS significant incidents' },
  'umd-cissm': { licence: 'ask', credit: 'Source: UMD CISSM' },
} as const;

describe('the AI-event sources', () => {
  for (const [id, want] of Object.entries(WIRED)) {
    it(`${id}: parser loads; pull, pattern, licence, credit match`, async () => {
      const s = src(id);
      expect(s.parser).toBe(want.parser);
      expect(s.pattern).toBe(want.pattern);
      expect(s.licence).toBe(want.licence);
      expect(s.credit).toBe(want.credit);
      expect(s.pull).toEqual(want.pull);
      expect(typeof (await loadParser(s.parser as string)).parse).toBe('function');
    });
  }

  it('aiaaic is not a heavy source any more', () => {
    expect(src('aiaaic').heavy).toBeUndefined();
  });

  it('each parser returns { records, unknownFields } for an input with no usable ID', async () => {
    const inputs: Record<string, unknown> = {
      avid: { data_type: 'AVID' },
      aiaaic: { 'AIAAIC ID#': '' },
      'cfr-cyber-ops': { Title: '' },
    };
    for (const [name, input] of Object.entries(inputs)) {
      expect((await loadParser(name)).parse(input)).toEqual({ records: [], unknownFields: [] });
    }
  });

  for (const [id, want] of Object.entries(UNWIRED)) {
    it(`${id} has no parser and no pull; its licence and credit are unchanged`, () => {
      const s = src(id);
      expect(s.parser).toBeUndefined();
      expect(s.pull).toBeUndefined();
      expect(s.licence).toBe(want.licence);
      expect(s.credit).toBe(want.credit);
    });
  }

  it('the parser files are Worker-safe', () => {
    for (const name of ['avid', 'aiaaic', 'cfr-cyber-ops']) {
      const text = sources[`../src/${name}.ts`] ?? '';
      expect(text.length, name).toBeGreaterThan(0);
      expect(text, name).not.toMatch(/node:|Buffer|process\.|require\(/);
    }
  });
});
