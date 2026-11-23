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
  'project-zero': {
    parser: 'project-zero',
    pattern: 'fingerprint',
    licence: 'ask',
    credit: 'Source: Project Zero 0-day sheet',
    fingerprint: {
      url: 'https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/export?format=csv&gid=1190662839',
      format: 'csv',
      key: 'CVE',
    },
  },
  enisa: {
    parser: 'euvd',
    pattern: 'fingerprint',
    licence: 'ask',
    credit: 'Source: ENISA (EUVD + EU KEV)',
    fingerprint: {
      url: 'https://euvdservices.enisa.europa.eu/api/search?exploited=true&page=0&size=100',
      format: 'json',
      itemsPath: 'items',
      key: 'id',
    },
  },
  gcve: {
    parser: 'gcve-sighting',
    pattern: 'fingerprint',
    licence: 'ask',
    credit: 'Source: GCVE',
    fingerprint: {
      url: 'https://db.gcve.eu/api/sighting/?type=exploited&per_page=100',
      format: 'json',
      itemsPath: 'data',
      key: 'uuid',
    },
  },
} as const;

describe('the sighting sources', () => {
  for (const [id, want] of Object.entries(WIRED)) {
    it(`${id}: parser loads; pull, pattern, licence, credit match`, async () => {
      const s = src(id);
      expect(s.parser).toBe(want.parser);
      expect(s.pattern).toBe(want.pattern);
      expect(s.licence).toBe(want.licence);
      expect(s.credit).toBe(want.credit);
      expect(s.pull).toEqual({ fingerprint: want.fingerprint });
      expect(typeof (await loadParser(s.parser as string)).parse).toBe('function');
    });
  }

  it('each parser returns { records, unknownFields } for an empty document', async () => {
    const inputs: Record<string, unknown> = {
      'project-zero': { CVE: '-' },
      euvd: { items: [], total: 0 },
      'gcve-sighting': { metadata: {}, data: [] },
    };
    for (const [name, input] of Object.entries(inputs)) {
      const out = (await loadParser(name)).parse(input);
      expect(out).toEqual({ records: [], unknownFields: [] });
    }
  });

  it('shadowserver has no parser and no pull; its licence and credit are unchanged', () => {
    const s = src('shadowserver');
    expect(s.parser).toBeUndefined();
    expect(s.pull).toBeUndefined();
    expect(s.licence).toBe('ask');
    expect(s.credit).toBe('Source: Shadowserver');
  });

  it('the parser files are Worker-safe', () => {
    for (const name of ['project-zero', 'euvd', 'gcve-sighting']) {
      const text = sources[`../src/${name}.ts`] ?? '';
      expect(text.length, name).toBeGreaterThan(0);
      expect(text, name).not.toMatch(/node:|Buffer|process\.|require\(/);
    }
  });
});
