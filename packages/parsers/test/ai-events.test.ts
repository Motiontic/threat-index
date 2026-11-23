import type { IncidentRecord } from '@ti/core/types';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { fetch as fingerprintFetch } from '../../patterns/src/fingerprint';
import { makeCtx, reply, route } from '../../patterns/test/helpers';
import { parseAiaaicRow } from '../src/aiaaic';
import { parseAvid } from '../src/avid';
import { cfrIncidentId, parseCfrRow } from '../src/cfr-cyber-ops';

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

async function rows(id: string, file: string): Promise<unknown[]> {
  const source = SOURCE_BY_ID.get(id);
  const url = source?.pull?.fingerprint?.url;
  if (!source || !url) throw new Error(`no fingerprint pull for ${id}`);
  const h = makeCtx({
    source,
    routes: [route(url, reply(fixture(id, file), 200, { 'content-type': 'text/csv' }))],
  });
  return (await fingerprintFetch(h.ctx)).items.map((i) => i.body);
}

describe('avid', () => {
  const FILES = [
    { file: 'AVID-2026-R1714.json', id: 'AVID-2026-R1714', date: '2026-03-23' },
    { file: 'AVID-2022-R0001.json', id: 'AVID-2022-R0001', date: '2022-11-09' },
    { file: 'AVID-2023-V028.json', id: 'AVID-2023-V028', date: '2023-03-31' },
  ];
  const expectedUrl = (id: string) =>
    id.includes('-R')
      ? `https://avidml.org/database/${id.toLowerCase()}/`
      : `https://github.com/avidml/avid-db/blob/main/vulnerabilities/${id.slice(5, 9)}/${id}.json`;

  for (const f of FILES) {
    it(`${f.id}: object, JSON text and GitFile give the same one ai record`, () => {
      const text = fixture('avid', f.file);
      const a = parseAvid(JSON.parse(text));
      const b = parseAvid(text);
      const c = parseAvid({ path: `reports/x/${f.file}`, status: 'added', text });
      expect(b).toEqual(a);
      expect(c).toEqual(a);
      expect(a.unknownFields).toEqual([]);
      expect(a.records).toHaveLength(1);
      const r = a.records[0] as IncidentRecord;
      expect(r).toMatchObject({ source: 'avid', incidentId: f.id, kind: 'ai', url: expectedUrl(f.id) });
      expect(r.date).toBe(f.date);
      expect(r.title.length).toBeGreaterThan(0);
      expect(r.title).not.toBe(f.id);
      expect(new Set(r.entities).size).toBe(r.entities?.length);
    });
  }

  it('R1714: title, published date, entities deduplicated, CWE technique', () => {
    const r = parseAvid(fixture('avid', 'AVID-2026-R1714.json')).records[0] as IncidentRecord;
    expect(r.title).toBe('Trivy ecosystem supply chain briefly compromised (CVE-2026-33634)');
    expect(r.entities).toEqual([
      'aquasecurity',
      'BerriAI',
      'setup-trivy',
      'trivy-action',
      'trivy',
      'LiteLLM',
    ]);
    expect(r.techniques).toEqual(['CWE-506']);
    // The live file carries `reported_date` only (the spec expected `published_date`); V028 covers `published_date`.
    expect(r.date).toBe('2026-03-23');
  });

  it('R0001 uses reported_date; V028 has developers, deployers and artifacts', () => {
    const old = parseAvid(fixture('avid', 'AVID-2022-R0001.json')).records[0] as IncidentRecord;
    expect(old.date).toBe('2022-11-09');
    expect(old.entities).toEqual(['HuggingFace', 'bert-base-uncased']);
    expect(old.techniques).toEqual([]);
    const v = parseAvid(fixture('avid', 'AVID-2023-V028.json')).records[0] as IncidentRecord;
    expect(v.entities).toEqual(['OpenAI', 'boxcars.ai', 'ChatGPT']);
  });

  it('a removed or empty GitFile gives nothing; a bad ID gives nothing', () => {
    const text = fixture('avid', 'AVID-2026-R1714.json');
    expect(parseAvid({ path: 'p', status: 'removed', text }).records).toEqual([]);
    expect(parseAvid({ path: 'p', status: 'modified', text: null }).records).toEqual([]);
    const bad = { ...JSON.parse(text), metadata: { report_id: 'AVID-26-R1' } };
    expect(parseAvid(bad).records).toEqual([]);
    expect(parseAvid({ data_type: 'AVID' }).records).toEqual([]);
  });

  it('reports an extra top-level field once; bad JSON and non-objects throw', () => {
    const doc = { ...JSON.parse(fixture('avid', 'AVID-2026-R1714.json')), extra: 1 };
    expect(parseAvid(doc).unknownFields).toEqual(['extra']);
    expect(() => parseAvid('{nope')).toThrow(/^avid:/);
    expect(() => parseAvid(['x'])).toThrow(/^avid:/);
    expect(() => parseAvid(null)).toThrow(/^avid:/);
    expect(() => parseAvid({ path: 'p', status: 'added', text: '{nope' })).toThrow(/^avid:/);
  });

  it('cuts a long title at a word boundary', () => {
    const doc = {
      ...JSON.parse(fixture('avid', 'AVID-2022-R0001.json')),
      problemtype: { description: { value: `${'word '.repeat(60)}end` } },
    };
    const t = (parseAvid(doc).records[0] as IncidentRecord).title;
    expect(t.length).toBeLessThanOrEqual(200);
    expect(t.endsWith('word')).toBe(true);
  });
});

describe('aiaaic', () => {
  it('one record per incident through the fingerprint pattern; no sub-header row, no date', async () => {
    const items = await rows('aiaaic', 'incidents.csv');
    expect(items).toHaveLength(6);
    const out = items.map((b) => parseAiaaicRow(b));
    for (const o of out) expect(o.unknownFields).toEqual([]);
    const recs = out.flatMap((o) => o.records);
    expect(recs).toHaveLength(6);
    for (const r of recs) {
      expect(r).toMatchObject({ source: 'aiaaic', kind: 'ai' });
      expect(r.incidentId).toMatch(/^AIAAIC\d+$/);
      expect(r.date).toBeUndefined();
      expect(r.techniques).toBeUndefined();
      expect(r.url).toMatch(/^https:\/\/www\.aiaaic\.org\//);
    }
    const by = (id: string) => recs.find((r) => r.incidentId === id) as IncidentRecord;
    expect(by('AIAAIC2261').entities).toEqual(
      expect.arrayContaining(['Anthropic', 'Google', 'Meta', 'Microsoft', 'Mistral', 'OpenAI', 'xAI']),
    );
    expect(by('AIAAIC2261').entities?.every((e) => !e.includes(';'))).toBe(true);
    expect(by('AIAAIC2064').entities).toBeDefined();
  });

  it('takes JSON text, accepts a full date, throws on non-objects and a missing ID key', () => {
    const row = {
      'AIAAIC ID#': ' AIAAIC9 ',
      'Incident headline': 'A  headline',
      Occurred: '2025-02-03',
      Deployer: 'Unknown; Acme',
      Extra: 'x',
    };
    const out = parseAiaaicRow(JSON.stringify(row));
    expect(out.unknownFields).toEqual(['Extra']);
    expect(out.records).toEqual([
      {
        source: 'aiaaic',
        incidentId: 'AIAAIC9',
        kind: 'ai',
        title: 'A headline',
        date: '2025-02-03',
        entities: ['Acme'],
      },
    ]);
    expect(parseAiaaicRow({ 'AIAAIC ID#': 'x', 'Incident headline': 'h' }).records).toEqual([]);
    expect(() => parseAiaaicRow('nope')).toThrow(/^aiaaic:/);
    expect(() => parseAiaaicRow({ Title: 'x' })).toThrow(/^aiaaic:/);
    expect(() => parseAiaaicRow(null)).toThrow(/^aiaaic:/);
  });
});

describe('cfr-cyber-ops', () => {
  async function recs(): Promise<IncidentRecord[]> {
    const items = await rows('cfr-tracker', 'incidents.csv');
    expect(items).toHaveLength(7);
    return items.flatMap((b) => {
      const o = parseCfrRow(b);
      expect(o.unknownFields).toEqual([]);
      return o.records;
    });
  }

  it('one cyber_op record per row; the two Roshan rows differ; ids are safe', async () => {
    const all = await recs();
    expect(all).toHaveLength(7);
    for (const r of all) {
      expect(r).toMatchObject({ source: 'cfr-tracker', kind: 'cyber_op' });
      expect(r.incidentId).toMatch(SAFE_ID);
    }
    const roshan = all.filter((r) => r.title.includes('Roshan'));
    expect(roshan).toHaveLength(2);
    expect(roshan[0]?.date).toBe(roshan[1]?.date);
    expect(roshan[0]?.incidentId).not.toBe(roshan[1]?.incidentId);
    expect(new Set(all.map((r) => r.incidentId)).size).toBe(7);
  });

  it('undated row, Also known as stripped, Sponsor first, no victim or description text', async () => {
    const all = await recs();
    const undated = all.find((r) => r.date === undefined);
    expect(undated?.incidentId.startsWith('undated:')).toBe(true);
    const nodaria = all.find((r) => r.title === 'Nodaria') as IncidentRecord;
    expect(nodaria.entities?.[0]).toBe('Russian Federation');
    expect(nodaria.entities).toContain('UAC-0056');
    expect(nodaria.entities).toContain('Ember Bear');
    expect(nodaria.entities?.some((e) => /^also known|^and /i.test(e))).toBe(false);
    const sandworm = all.find((r) => r.title === 'Sandworm') as IncidentRecord;
    expect(sandworm.entities?.slice(0, 2)).toEqual(['Russian Federation', 'Voodoo Bear']);
    // `Affiliations` is free text: the parser splits it, it does not interpret it.
    expect(sandworm.entities?.every((e) => e.length <= 100)).toBe(true);
    const antlion = all.find((r) => r.title === 'Antlion') as IncidentRecord;
    expect(antlion.entities).toEqual([]);
    const sources = await rows('cfr-tracker', 'incidents.csv');
    for (const [i, b] of sources.entries()) {
      const row = b as Record<string, string>;
      const r = all[i] as IncidentRecord;
      const stored = JSON.stringify(r);
      for (const cell of [row.Victims, row.Description, row.Response])
        if (cell && cell.length > 20) expect(stored).not.toContain(cell.slice(0, 20));
      expect(r.url).toMatch(/^https?:\/\//);
    }
  });

  it('cfrIncidentId is stable, hashes the raw cells and slugs the title', () => {
    const a = cfrIncidentId('Targeting of Roshan!', '2021-09-28', 'Calypso');
    expect(cfrIncidentId('Targeting of Roshan!', '2021-09-28', 'Calypso')).toBe(a);
    expect(a).toMatch(/^2021-09-28:targeting-of-roshan:[0-9a-f]{8}$/);
    expect(cfrIncidentId('Targeting of Roshan!', '2021-09-28', 'RedFoxTrot')).not.toBe(a);
    expect(cfrIncidentId('x', null, '')).toMatch(/^undated:x:[0-9a-f]{8}$/);
    // FNV-1a 32-bit of "a" + "\u001f\u001f" is fixed.
    expect(cfrIncidentId('é', null, '')).toMatch(SAFE_ID);
    const long = cfrIncidentId(`${'ab '.repeat(40)}`, '2020-01-01', '');
    expect(long.split(':')[1]?.length).toBeLessThanOrEqual(60);
    expect(long.split(':')[1]?.endsWith('-')).toBe(false);
    expect(long).toMatch(SAFE_ID);
  });

  it('takes JSON text, throws on non-objects and a missing Title key, reports extras', () => {
    const out = parseCfrRow(
      JSON.stringify({
        Title: 'T',
        Date: '2020-02-30',
        Extra: 1,
        Sources_2: 'ftp://x',
        Sources_3: 'https://y.test/',
      }),
    );
    expect(out.unknownFields).toEqual(['Extra']);
    expect(out.records[0]).toMatchObject({ title: 'T', url: 'https://y.test/' });
    expect(out.records[0]?.date).toBeUndefined();
    expect(parseCfrRow({ Title: '  ' }).records).toEqual([]);
    expect(() => parseCfrRow('nope')).toThrow(/^cfr-cyber-ops:/);
    expect(() => parseCfrRow({ Date: 'x' })).toThrow(/^cfr-cyber-ops:/);
    expect(() => parseCfrRow([])).toThrow(/^cfr-cyber-ops:/);
  });
});
