import { describe, expect, it } from 'vitest';
import {
  MAX_PREFIX,
  resolvePrefix,
  searchManifestKey,
  searchShardKey,
  searchTerms,
  shardPrefix,
  shardPrefixAt,
} from './search';

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
    expect(shardPrefix('x')).toBe('x~');
    expect(shardPrefix('')).toBe('~~');
  });
  it('replaces odd characters with _', () => {
    expect(shardPrefix('-a')).toBe('_a');
    expect(shardPrefix('über')).toBe('_b');
    expect(shardPrefix('a.b')).toBe('a_');
    expect(shardPrefix('漢字')).toBe('__');
  });
});

describe('shardPrefixAt and resolvePrefix', () => {
  it('goes deeper and pads short terms with ~', () => {
    expect(shardPrefixAt('apache', 4)).toBe('apac');
    expect(shardPrefixAt('ap', 4)).toBe('ap~~');
    expect(shardPrefixAt('a.b-c', 5)).toBe('a_b_c');
  });
  it('follows splits one character at a time', () => {
    const splits = new Set(['ap', 'apa']);
    expect(resolvePrefix('apache', splits)).toBe('apac');
    expect(resolvePrefix('api', splits)).toBe('ap'.concat('i'));
    expect(resolvePrefix('ap', splits)).toBe('ap~');
    expect(resolvePrefix('log4j', splits)).toBe('lo');
  });
  it('is bounded when every prefix claims to be split', () => {
    const all = new Set<string>();
    for (let d = 2; d <= MAX_PREFIX; d++) all.add(shardPrefixAt('aaa', d));
    expect(resolvePrefix('aaa', all)).toHaveLength(MAX_PREFIX);
  });
});

describe('keys', () => {
  it('builds the R2 keys', () => {
    expect(searchShardKey('cv')).toBe('lookup/search/v2/cv.json');
    expect(searchManifestKey()).toBe('lookup/search/v2/manifest.json');
  });
});
