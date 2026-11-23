import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { check as gitCheck } from '../../patterns/src/git';
import { makeCtx, reply, route, SHA_A } from '../../patterns/test/helpers';
import { SOURCE_BY_ID } from '../../sources/src/registry';
import { loadParser } from '../src/load';
import { MAX_POC_PER_CVE } from '../src/poc-in-github';
import { parseTrickestCve } from '../src/trickest-cve';

const TODAY = new Date('2026-11-24T10:00:00Z');
const real = fixture('trickest-cve', 'CVE-2024-3400.md');
const edge = fixture('trickest-cve', 'edge-cases.md');
const refOnly = fixture('trickest-cve', 'reference-only.md');
const file = (path: string, text: string | null, status: 'added' | 'removed' = 'added') => ({
  path,
  status,
  text,
});

const rec = (vulnKey: string, ref: string) => ({
  vulnKey,
  kind: 'poc',
  source: 'trickest-cve',
  ref,
  firstSeen: '2026-11-24',
  url: `https://github.com/${ref}`,
});

describe('trickest-cve parser', () => {
  it('turns the real file into its five links, exactly', () => {
    const out = parseTrickestCve(file('2024/CVE-2024-3400.md', real), TODAY);
    expect(out).toEqual({
      records: [
        '0day404/HV-2024-POC',
        '0x0d3ad/CVE-2024-3400',
        '0xAj-Krishna/biggest-hack',
        '0xAj-Krishna/biggest-hack-2023-24',
        '0xMarcio/cve',
      ].map((r) => rec('CVE-2024-3400', r)),
      unknownFields: [],
      skipped: 0,
    });
  });

  it('keeps a repeated link once, skips deep paths and other hosts, reports unknown headings', () => {
    const out = parseTrickestCve(file('2025/CVE-2025-0001.md', edge), TODAY);
    expect(out.records.map((r) => r.ref)).toEqual(['alice/poc-one', 'bob/poc-two', 'erin/poc-five']);
    expect(out.skipped).toBe(2);
    expect(out.unknownFields).toEqual(['heading:Extra']);
  });

  it('reads nothing outside the Github section', () => {
    const out = parseTrickestCve(file('2025/CVE-2025-0002.md', refOnly), TODAY);
    expect(out).toEqual({ records: [], unknownFields: [], skipped: 0 });
    const inEdge = parseTrickestCve(file('2025/CVE-2025-0001.md', edge), TODAY);
    expect(inEdge.records.map((r) => r.ref)).not.toContain('frank/not-read');
  });

  it('matches the heading case-insensitively', () => {
    const text = '#### GITHUB\n- https://github.com/a/b\n';
    expect(parseTrickestCve(file('2025/CVE-2025-0003.md', text), TODAY).records).toHaveLength(1);
  });

  it('removed and null text give nothing; a path that is not a CVE file gives nothing', () => {
    const none = { records: [], unknownFields: [], skipped: 0 };
    expect(parseTrickestCve(file('2024/CVE-2024-3400.md', null, 'removed'), TODAY)).toEqual(none);
    expect(parseTrickestCve(file('2024/CVE-2024-3400.md', null), TODAY)).toEqual(none);
    expect(parseTrickestCve(file('2024/README.md', real), TODAY)).toEqual(none);
    expect(parseTrickestCve(file('2024/CVE-2024-3400.json', real), TODAY)).toEqual(none);
  });

  it('throws on input that is not a GitFile', () => {
    expect(() => parseTrickestCve(5, TODAY)).toThrow('trickest-cve: input must be a GitFile');
    expect(() => parseTrickestCve({ path: 'x' }, TODAY)).toThrow('trickest-cve: input must be a GitFile');
    expect(() => parseTrickestCve(null, TODAY)).toThrow('trickest-cve: input must be a GitFile');
  });

  it('cuts a long list to MAX_POC_PER_CVE, in file order', () => {
    const links = Array.from({ length: MAX_POC_PER_CVE + 10 }, (_, i) => `- https://github.com/u${i}/r${i}`);
    const text = `#### Github\n${links.join('\n')}\n`;
    const out = parseTrickestCve(file('2025/CVE-2025-0004.md', text), TODAY);
    expect(out.records).toHaveLength(MAX_POC_PER_CVE);
    expect(out.records[0]?.ref).toBe('u0/r0');
    expect(out.records[MAX_POC_PER_CVE - 1]?.ref).toBe(`u${MAX_POC_PER_CVE - 1}/r${MAX_POC_PER_CVE - 1}`);
  });
});

describe('trickest-cve wiring', () => {
  const source = SOURCE_BY_ID.get('trickest-cve');
  it('has the parser and pull blocks, and keeps its licence and cadence', () => {
    expect(source).toMatchObject({
      pattern: 'git',
      parser: 'trickest-cve',
      licence: 'on',
      cadence: 'daily',
      pull: { git: { repo: 'trickest/cve', branch: 'main', include: ['*/CVE-*.md'] } },
    });
  });

  it('loadParser finds the parser and it parses the fixture', async () => {
    const mod = await loadParser('trickest-cve');
    const out = mod.parse(file('2024/CVE-2024-3400.md', real));
    const records = Array.isArray(out) ? out : out.records;
    expect(records).toHaveLength(5);
  });

  it('git check: a 304 is unchanged', async () => {
    if (!source) throw new Error('no source trickest-cve');
    const h = makeCtx({
      source,
      cursor: { kind: 'commit', value: SHA_A },
      routes: [route('https://api.github.com/repos/trickest/cve/commits/main', reply(null, 304))],
    });
    expect(await gitCheck(h.ctx)).toBe('unchanged');
  });
});
