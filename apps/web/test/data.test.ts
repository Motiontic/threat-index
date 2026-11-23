import { NVD_NOTICE } from '@ti/core/licence';
import { SOURCES } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import {
  getData,
  homeData,
  indexEntries,
  listSources,
  lookupEntry,
  MAX_QUERY,
  MAX_RESULTS,
  SAMPLE_DATA,
  searchEntries,
} from '../app/data/data.server';
import { FIXTURE_ENTRIES } from '../app/data/fixtures.server';

describe('entry lookup', () => {
  it('finds an entry by key, in any case', () => {
    expect(lookupEntry('CVE-2025-3248')?.entry.key).toBe('CVE-2025-3248');
    expect(lookupEntry('cve-2025-3248')?.entry.key).toBe('CVE-2025-3248');
    expect(lookupEntry('  CVE-2025-3248 ')?.entry.key).toBe('CVE-2025-3248');
  });

  it('finds an entry by alias, in any case', () => {
    expect(lookupEntry('GHSA-c995-4fw3-j39m')?.entry.key).toBe('CVE-2025-3248');
    expect(lookupEntry('ghsa-c995-4fw3-j39m')?.entry.key).toBe('CVE-2025-3248');
    expect(lookupEntry('GHSA-jfh8-c2jp-5v3q')?.entry.key).toBe('CVE-2021-44228');
  });

  it('returns null for unknown or over-long IDs', () => {
    expect(lookupEntry('CVE-1999-99999')).toBeNull();
    expect(lookupEntry('')).toBeNull();
    expect(lookupEntry('A'.repeat(101))).toBeNull();
  });

  it('returns only the preview fields, never anything from the full record', () => {
    const res = lookupEntry('CVE-2025-3248');
    expect(res?.access).toBe('preview');
    expect(Object.keys(res ?? {}).sort()).toEqual(['access', 'credits', 'entry']);
    expect(Object.keys(res?.entry ?? {}).sort()).toEqual(
      ['aliases', 'cvss', 'key', 'kev_added', 'published', 'subtitle', 'summary', 'title', 'type'].sort(),
    );
  });

  it('carries the facts from the spec', () => {
    const e = lookupEntry('CVE-2021-44228')?.entry;
    expect(e).toMatchObject({ published: '2021-12-10', cvss: 10, kev_added: '2021-12-10' });
    expect(lookupEntry('CVE-2024-3094')?.entry.kev_added).toBeNull();
  });

  it('credits each cited source, with the NVD notice exactly once when NVD is cited', () => {
    const cited = lookupEntry('CVE-2025-3248');
    expect(cited?.credits.filter((c) => c === NVD_NOTICE)).toHaveLength(1);
    expect(cited?.credits).toContain('Source: CISA KEV');
    expect(new Set(cited?.credits).size).toBe(cited?.credits.length);
    const uncited = lookupEntry('T1190');
    expect(uncited?.credits).not.toContain(NVD_NOTICE);
  });
});

describe('search', () => {
  it('matches case-insensitively on key, alias, title, subtitle and summary', () => {
    expect(searchEntries({ q: 'LOG4J' }).results.map((r) => r.key)).toContain('CVE-2021-44228');
    expect(searchEntries({ q: 'ghsa-c995' }).results.map((r) => r.key)).toEqual(['CVE-2025-3248']);
    expect(searchEntries({ q: 'glibc' }).results.map((r) => r.key)).toContain('CVE-2024-6387');
    expect(searchEntries({ q: 'GlobalProtect gateway' }).results.map((r) => r.key)).toContain(
      'CVE-2024-3400',
    );
  });

  it('puts an exact key or alias first', () => {
    const byKey = searchEntries({ q: 'KEV' });
    expect(byKey.results[0]?.key).toBe('KEV');
    expect(byKey.total).toBeGreaterThanOrEqual(1);
    expect(searchEntries({ q: 'cve-2025-3248' }).results[0]?.key).toBe('CVE-2025-3248');
    expect(searchEntries({ q: 'ghsa-jfh8-c2jp-5v3q' }).results[0]?.key).toBe('CVE-2021-44228');
  });

  it('filters by type and by the kev signal, and ignores unknown values', () => {
    const vulns = searchEntries({ type: ['vuln'] });
    expect(vulns.results.every((r) => r.type === 'vuln')).toBe(true);
    const kev = searchEntries({ sig: ['kev'] });
    expect(kev.results.length).toBeGreaterThan(0);
    expect(kev.results.every((r) => r.kev_added !== null)).toBe(true);
    const ignored = searchEntries({ type: ['nope'], sig: ['nope'] });
    expect(ignored.params.type).toEqual([]);
    expect(ignored.params.sig).toEqual([]);
    expect(ignored.total).toBe(FIXTURE_ENTRIES.length);
  });

  it('cuts q to 200 characters', () => {
    const res = searchEntries({ q: 'a'.repeat(500) });
    expect(res.params.q).toHaveLength(MAX_QUERY);
    expect(MAX_QUERY).toBe(200);
  });

  it('sorts by relevance by default with q, and newest on request', () => {
    expect(searchEntries({ q: 'x' }).params.sort).toBe('rel');
    const newest = searchEntries({ type: ['vuln'], sort: 'new' }).results.map((r) => r.published ?? '');
    expect(newest).toEqual([...newest].sort().reverse());
  });

  it('returns at most 20 results but reports the full count', () => {
    expect(MAX_RESULTS).toBe(20);
    const res = searchEntries({});
    expect(res.results.length).toBeLessThanOrEqual(20);
    expect(res.total).toBe(FIXTURE_ENTRIES.length);
  });
});

describe('index', () => {
  it('has buckets a to z and 0, with counts that add up', () => {
    const { buckets } = indexEntries(null);
    expect(buckets.map((b) => b.letter)).toEqual([...'abcdefghijklmnopqrstuvwxyz', '0']);
    expect(buckets.reduce((n, b) => n + b.count, 0)).toBe(FIXTURE_ENTRIES.length);
    for (const b of buckets) expect(b.entries).toHaveLength(b.count);
  });

  it('puts keys that start with a letter under it and the rest under 0', () => {
    const by = Object.fromEntries(
      indexEntries(null).buckets.map((b) => [b.letter, b.entries.map((e) => e.key)]),
    );
    expect(by.c).toContain('CVE-2025-3248');
    expect(by.t).toContain('T1190');
    expect(by.e).toContain('EPSS');
  });

  it('narrows to one letter', () => {
    const { buckets } = indexEntries('k');
    expect(buckets).toHaveLength(1);
    expect(buckets[0]?.entries.map((e) => e.key)).toEqual(['KEV']);
  });
});

describe('sources', () => {
  it('lists all 55 sources with a sample last-success time, none for wait', () => {
    const res = listSources();
    expect(res.rows).toHaveLength(SOURCES.length);
    expect(res.counts.all).toBe(55);
    for (const r of res.rows) {
      if (r.licence === 'wait') expect(r.lastSuccess).toBeNull();
      else expect(r.lastSuccess).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it('filters by licence status and ignores unknown ones', () => {
    for (const status of ['on', 'ask', 'wait', 'link'] as const) {
      const res = listSources(status);
      expect(res.rows.every((r) => r.licence === status)).toBe(true);
      expect(res.rows).toHaveLength(res.counts[status]);
    }
    expect(listSources('bogus').rows).toHaveLength(55);
    const c = listSources().counts;
    expect(c.on + c.ask + c.wait + c.link).toBe(55);
  });
});

describe('home', () => {
  it('computes tile counts from the fixtures', () => {
    const tiles = Object.fromEntries(homeData().tiles.map((t) => [t.type, t.count]));
    const of = (type: string) => FIXTURE_ENTRIES.filter((e) => e.type === type).length;
    expect(tiles.vuln).toBe(of('vuln'));
    expect(tiles.breach).toBe(of('breach'));
    expect(tiles.ai).toBe(of('ai'));
    expect(tiles.mal).toBe(of('mal'));
    expect(tiles.kev).toBe(FIXTURE_ENTRIES.filter((e) => e.kev_added).length);
  });

  it('lists latest KEV additions newest first, and example breaches', () => {
    const { kev, breaches } = homeData();
    const dates = kev.map((e) => e.kev_added ?? '');
    expect(dates).toEqual([...dates].sort().reverse());
    expect(breaches.every((e) => e.type === 'breach')).toBe(true);
  });
});

describe('getData', () => {
  it('exposes the five lookups and says it is sample data', () => {
    const d = getData(new Request('https://example.test/'));
    expect(Object.keys(d).sort()).toEqual(['entry', 'home', 'index', 'search', 'sources']);
    expect(SAMPLE_DATA).toBe(true);
  });
});
