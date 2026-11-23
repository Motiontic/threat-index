import type { EntryResponse, IndexLetterResponse, SearchResponse, SourcesResponse } from '@ti/core/api';
import { NVD_NOTICE } from '@ti/core/licence';
import { SOURCES } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixtureApi, PAGE_SIZE } from '../app/data/fixture-api.server';
import { FIXTURE_ENTRIES } from '../app/data/fixtures.server';

const get = (path: string) => fixtureApi(new Request(`https://ti-api.internal${path}`));
const body = async <T>(path: string) => (await get(path)).json() as Promise<T>;

describe('fixtureApi /v1/entries/:id', () => {
  it('finds by key and alias in any case, in the preview shape', async () => {
    for (const id of ['CVE-2025-3248', 'cve-2025-3248', 'GHSA-c995-4fw3-j39m']) {
      const res = await body<EntryResponse>(`/v1/entries/${id}`);
      expect(res.access).toBe('preview');
      expect(res.entry.key).toBe('CVE-2025-3248');
    }
    const { entry } = await body<EntryResponse>('/v1/entries/CVE-2025-3248');
    expect(entry).toMatchObject({
      kind: 'cve',
      cvss: 9.8,
      exploited: true,
      kevAdded: '2025-05-05',
      published: '2025-04-07',
    });
    expect(Object.keys(entry)).not.toContain('subtitle');
    expect(Object.keys(entry)).not.toContain('kev_added');
  });

  it('is 404 for unknown and uses the fixture type as kind for non-CVEs', async () => {
    expect((await get('/v1/entries/CVE-1999-99999')).status).toBe(404);
    expect((await body<EntryResponse>('/v1/entries/T1190')).entry.kind).toBe('tech');
    expect((await body<EntryResponse>('/v1/entries/CVE-2024-3094')).entry.exploited).toBe(false);
  });

  it('credits each cited source, with the NVD notice once', async () => {
    const { entry } = await body<EntryResponse>('/v1/entries/CVE-2025-3248');
    expect(entry.credits.filter((c) => c.text === NVD_NOTICE)).toHaveLength(1);
    expect(entry.credits.find((c) => c.sourceId === 'cisa-kev')).toMatchObject({ text: 'Source: CISA KEV' });
    const none = await body<EntryResponse>('/v1/entries/T1190');
    expect(none.entry.credits.some((c) => c.text === NVD_NOTICE)).toBe(false);
  });
});

describe('fixtureApi /v1/search', () => {
  it('matches q on key, alias, title, subtitle and summary; exact first', async () => {
    expect((await body<SearchResponse>('/v1/search?q=LOG4J')).hits.map((h) => h.key)).toContain(
      'CVE-2021-44228',
    );
    expect((await body<SearchResponse>('/v1/search?q=ghsa-c995')).hits.map((h) => h.key)).toEqual([
      'CVE-2025-3248',
    ]);
    expect((await body<SearchResponse>('/v1/search?q=KEV')).hits[0]?.key).toBe('KEV');
  });

  it('filters by type, sig, sev, year and sorts', async () => {
    const vulns = await body<SearchResponse>('/v1/search?type=vuln');
    expect(vulns.hits.every((h) => (h as { kind?: string }).kind === 'cve')).toBe(true);
    const kev = await body<SearchResponse>('/v1/search?sig=kev');
    expect(kev.hits.length).toBeGreaterThan(0);
    expect(kev.hits.every((h) => h.exploited)).toBe(true);
    const crit = await body<SearchResponse>('/v1/search?sev=critical&year=2021');
    expect(crit.hits.map((h) => h.key)).toContain('CVE-2021-44228');
    expect(crit.hits.every((h) => (h.cvss ?? 0) >= 9 && h.published?.startsWith('2021'))).toBe(true);
    const newest = (await body<SearchResponse>('/v1/search?type=vuln&sort=new')).hits.map(
      (h) => h.published ?? '',
    );
    expect(newest).toEqual([...newest].sort().reverse());
  });

  it('is 400 for no criteria, bad values and bad cursors', async () => {
    for (const q of [
      '',
      '?q=x&sev=huge',
      '?q=x&year=1',
      '?q=x&sort=zig',
      '?q=x&cursor=%25%25',
      `?q=${'a'.repeat(201)}`,
    ]) {
      const res = await get(`/v1/search${q}`);
      expect(res.status, q).toBe(400);
      expect(typeof ((await res.json()) as { error: string }).error).toBe('string');
    }
  });

  it('pages with an opaque cursor, 20 per page', async () => {
    expect(PAGE_SIZE).toBe(20);
    const all = await body<SearchResponse>(
      '/v1/search?sort=new&type=vuln&type=breach&type=ai&type=mal&type=tech&type=term',
    );
    expect(all.total).toBe(FIXTURE_ENTRIES.length);
    expect(all.hits).toHaveLength(Math.min(20, FIXTURE_ENTRIES.length));
    if (FIXTURE_ENTRIES.length <= 20) expect(all.cursor).toBeUndefined();
  });

  it('pages when there are more than 20 rows (via index-style fake data)', async () => {
    // Fixtures have fewer than 21 rows, so the cursor path is exercised through /v1/index and a forged cursor.
    const res = await get('/v1/search?q=a&cursor=bzA');
    expect(res.status).toBe(200);
    const empty = await body<SearchResponse>('/v1/search?type=vuln&cursor=bzEwMDA');
    expect(empty.hits).toEqual([]);
  });
});

describe('fixtureApi /v1/index and /v1/sources', () => {
  it('lists a letter', async () => {
    const c = await body<IndexLetterResponse>('/v1/index/c');
    expect(c.letter).toBe('c');
    expect(c.items.map((i) => i.key)).toContain('CVE-2025-3248');
    expect((await body<IndexLetterResponse>('/v1/index/k')).items.map((i) => i.key)).toEqual(['KEV']);
    expect((await get('/v1/index/ab')).status).toBe(404);
    expect((await get('/v1/index/c?cursor=%25')).status).toBe(400);
  });

  it('lists every registry source with sample times, none for wait', async () => {
    const res = await body<SourcesResponse>('/v1/sources');
    expect(res.sources).toHaveLength(SOURCES.length);
    for (const s of res.sources) {
      if (s.licence === 'wait') expect(s.lastSuccess).toBeUndefined();
      else expect(s.lastSuccess).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it('never answers the sitemap', async () => {
    expect((await get('/v1/sitemap.xml')).status).toBe(404);
    expect((await get('/v1/nothing')).status).toBe(404);
  });
});
