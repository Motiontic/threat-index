import { describe, expect, it } from 'vitest';
import { searchShardKey, searchTerms, shardPrefix } from './search';

describe('searchTerms', () => {
  it('keeps CVE and GHSA IDs whole', () => {
    expect(searchTerms('Fix CVE-2025-3248 now')).toEqual(['fix', 'cve-2025-3248', 'now']);
    expect(searchTerms('GHSA-abcd-1234-wxyz')).toEqual(['ghsa-abcd-1234-wxyz']);
  });
  it('splits on punctuation and keeps . and _', () => {
    expect(searchTerms('foo, bar; (baz) a.b c_d')).toEqual(['foo', 'bar', 'baz', 'a.b', 'c_d']);
  });
  it('drops terms under 2 characters', () => {
    expect(searchTerms('a bb c dd')).toEqual(['bb', 'dd']);
  });
  it('handles unicode letters', () => {
    expect(searchTerms('Überlauf Ünïcode 漢字')).toEqual(['überlauf', 'ünïcode', '漢字']);
  });
  it('keeps unique terms in order', () => {
    expect(searchTerms('Beta alpha BETA alpha gamma')).toEqual(['beta', 'alpha', 'gamma']);
  });
  it('returns [] for empty or punctuation-only text', () => {
    expect(searchTerms('')).toEqual([]);
    expect(searchTerms('!!! ??')).toEqual([]);
  });
});

describe('shardPrefix', () => {
  it('takes the first two characters, lowercase', () => {
    expect(shardPrefix('cve-2025-3248')).toBe('cv');
    expect(shardPrefix('Apache')).toBe('ap');
  });
  it('handles short terms', () => {
    expect(shardPrefix('x')).toBe('x');
    expect(shardPrefix('')).toBe('');
  });
  it('replaces odd characters with _', () => {
    expect(shardPrefix('-a')).toBe('_a');
    expect(shardPrefix('über')).toBe('_b');
    expect(shardPrefix('a.b')).toBe('a_');
    expect(shardPrefix('漢字')).toBe('__');
  });
});

describe('searchShardKey', () => {
  it('builds the R2 key', () => {
    expect(searchShardKey('cv')).toBe('lookup/search/cv.json');
  });
});
