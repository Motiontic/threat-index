import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { loadParser } from '../src/load';

const src = (id: string) => {
  const s = SOURCE_BY_ID.get(id);
  if (!s) throw new Error(`no source ${id}`);
  return s;
};

const WIRED = {
  'sec-edgar': {
    parser: 'sec-edgar',
    pattern: 'feed',
    licence: 'on',
    cadence: '3h',
    pull: {
      feed: {
        url: 'https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent&type=8-K&company=&dateb=&owner=include&start=0&count=100&output=atom',
        order: 'newest-first',
      },
    },
  },
  'hhs-ocr': {
    parser: 'hhs-ocr',
    pattern: 'page',
    licence: 'on',
    cadence: 'daily',
    pull: {
      page: {
        url: 'https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf',
        item: 'tbody[id$="reportResultTable_data"] > tr',
        key: 'name',
        order: 'newest-first',
        fields: {
          name: 'td:nth-child(2)',
          state: 'td:nth-child(3)',
          entityType: 'td:nth-child(4)',
          individuals: 'td:nth-child(5)',
          submitted: 'td:nth-child(6)',
          breachType: 'td:nth-child(7)',
          location: 'td:nth-child(8)',
          associate: 'td:nth-child(9)',
        },
      },
    },
  },
  'ca-ag': {
    parser: 'ca-ag',
    pattern: 'page',
    licence: 'ask',
    cadence: 'daily',
    pull: {
      page: {
        url: 'https://oag.ca.gov/privacy/databreach/list',
        item: 'table.views-table > tbody > tr',
        key: 'link',
        order: 'newest-first',
        fields: {
          name: 'td.views-field-field-sb24-org-name > a',
          link: { selector: 'td.views-field-field-sb24-org-name > a', attr: 'href' },
          breachDates: 'td.views-field-field-sb24-breach-date',
          reported: 'td.views-field-created',
        },
      },
    },
  },
  'wa-ag': {
    parser: 'wa-ag',
    pattern: 'fingerprint',
    licence: 'ask',
    cadence: 'daily',
    pull: {
      fingerprint: {
        url: 'https://data.wa.gov/resource/sb4j-ca4h.json?$order=datesubmitted%20DESC,id%20DESC&$limit=5000',
        format: 'json',
        key: 'id',
      },
    },
  },
} as const;

describe('the US breach-notice sources', () => {
  for (const [id, want] of Object.entries(WIRED)) {
    it(`${id}: parser loads; pattern, pull, licence and cadence match`, async () => {
      const s = src(id);
      expect(s.parser).toBe(want.parser);
      expect(s.pattern).toBe(want.pattern);
      expect(s.licence).toBe(want.licence);
      expect(s.cadence).toBe(want.cadence);
      expect(s.credit).toBe(`Source: ${s.name}`);
      expect(s.pull).toEqual(want.pull);
      expect(typeof (await loadParser(s.parser as string)).parse).toBe('function');
    });
  }

  it('state-ags stays unwired', () => {
    expect(src('state-ags').parser).toBeUndefined();
    expect(src('state-ags').pull).toBeUndefined();
  });
});
