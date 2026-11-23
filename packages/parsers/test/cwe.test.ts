import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { parseMitreCatalog } from '../src/cwe';

const cwe = fixture('cwe', 'cwec-sample.xml');
const capec = fixture('capec', 'capec-sample.xml');

describe('cwe parser (CWE and CAPEC)', () => {
  it('reads CWE entries, versions, parents and decodes entities', () => {
    const out = parseMitreCatalog(cwe);
    expect(out.version).toBe('5.0');
    expect(out.unknownFields).toEqual([]);
    expect(out.records.map((r) => r.id)).toEqual(['CWE-74', 'CWE-79', 'CWE-89']);
    expect(out.records.every((r) => r.framework === 'cwe')).toBe(true);
    const byId = Object.fromEntries(out.records.map((r) => [r.id, r]));
    expect(byId['CWE-74']?.parent).toBe('CWE-707');
    expect(byId['CWE-79']?.parent).toBe('CWE-74'); // the View 1000 Primary one, not the first ChildOf
    expect(byId['CWE-89']?.parent).toBe('CWE-74');
    expect(byId['CWE-79']?.name).toBe(
      "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    );
    expect(byId['CWE-79']?.summary).toBe(
      'The product does not neutralize user-controllable input before it is placed in output, e.g. a <script> tag & friends! Café.',
    );
    expect(byId['CWE-89']?.summary).toBe(
      'The product constructs all or part of an SQL command using externally-influenced input.',
    );
  });

  it('skips deprecated entries and categories', () => {
    const ids = parseMitreCatalog(cwe).records.map((r) => r.id);
    expect(ids).not.toContain('CWE-16');
    expect(ids).not.toContain('CWE-19');
  });

  it('reads CAPEC by its root element', () => {
    const out = parseMitreCatalog(capec);
    expect(out.version).toBe('3.9');
    expect(out.records).toEqual([
      {
        id: 'CAPEC-66',
        framework: 'capec',
        name: 'SQL Injection',
        summary: 'This attack exploits target software that constructs SQL statements based on user input.',
        parent: 'CAPEC-248',
      },
      {
        id: 'CAPEC-248',
        framework: 'capec',
        name: 'Command Injection',
        summary: 'An adversary looks for ways to execute commands & inject them.',
      },
    ]);
  });

  it('cuts long summaries to 300 characters at a word boundary', () => {
    const long = cwe.replace('does not neutralize special elements.', `${'word '.repeat(100)}`);
    const s = parseMitreCatalog(long).records[0]?.summary ?? '';
    expect(s.length).toBeLessThanOrEqual(300);
    expect(s.endsWith('word')).toBe(true);
  });

  it('throws for non-text input, the wrong root, and a missing version', () => {
    expect(() => parseMitreCatalog({})).toThrow('cwe: expected XML text');
    expect(() => parseMitreCatalog('<Other Version="1"/>')).toThrow(/^cwe: /);
    expect(() => parseMitreCatalog('not xml')).toThrow(/^cwe: /);
    expect(() => parseMitreCatalog('<Weakness_Catalog Name="CWE"></Weakness_Catalog>')).toThrow(/^cwe: /);
  });

  it('parses a 15 MB catalogue in under 5 seconds', () => {
    const start = cwe.indexOf('<Weakness ID="79"');
    const end = cwe.indexOf('</Weakness>', start) + '</Weakness>'.length;
    const entry = cwe.slice(start, end);
    const n = Math.ceil((15 * 1024 * 1024) / entry.length);
    const big = `<Weakness_Catalog Name="CWE" Version="9.9">${entry.repeat(n)}</Weakness_Catalog>`;
    expect(big.length).toBeGreaterThanOrEqual(15 * 1024 * 1024);
    const t0 = performance.now();
    const out = parseMitreCatalog(big);
    const ms = performance.now() - t0;
    expect(out.records).toHaveLength(n);
    expect(ms).toBeLessThan(5000);
  });
});
