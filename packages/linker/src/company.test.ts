import { describe, expect, it } from 'vitest';
import {
  companyRow,
  hintKey,
  incidentSpan,
  jurisdictionCode,
  nameKey,
  normaliseName,
  spansClose,
} from './company';

describe('normaliseName', () => {
  it.each([
    ['AT&T Inc.', 'at and t'],
    ['AT&T', 'at and t'],
    ['The Clorox Company', 'clorox'],
    ['UnitedHealth Group Incorporated', 'unitedhealth group'],
    ['Acme Holdings, L.L.C.', 'acme holdings'],
    ['Acme Co., Ltd.', 'acme'],
    ['First Bank, N.A.', 'first bank'],
    ['Foo Corp Inc', 'foo'],
    ['Café Zoë SA', 'cafe zoe'],
    ['Sunrise Dental d/b/a Smile Bright', 'sunrise dental'],
    ['Sunrise Dental DBA Smile Bright', 'sunrise dental'],
    ['  MGM   Resorts-International ', 'mgm resorts international'],
    ['Acme Health', 'acme health'],
    ['The Inc', 'inc'], // stripping would leave nothing: keep the name before the suffixes
    ['Co', 'co'],
    ['The', ''],
    ['', ''],
    ['!!!', ''],
  ])('%s -> %s', (raw, want) => expect(normaliseName(raw)).toBe(want));

  it('is stable when applied twice', () => {
    for (const n of ['AT&T Inc.', 'The Foo Co., LLC', 'Zoë dba Bar']) {
      const once = normaliseName(n);
      expect(normaliseName(once)).toBe(once);
    }
  });
});

describe('hintKey', () => {
  it('pads a CIK to ten digits', () => {
    expect(hintKey('cik:731766')).toEqual({ key: 'cik:0000731766', cik: '0000731766' });
    expect(hintKey('cik:0000731766')?.key).toBe('cik:0000731766');
  });
  it('rejects a bad CIK', () => {
    for (const bad of ['cik:', 'cik:12345678901', 'cik:12a', 'cik:-1', 'CIK 123', 'cik: 1 2'])
      expect(hintKey(bad), bad).toBeNull();
  });
  it('lower-cases a domain and drops a leading www.', () => {
    expect(hintKey('domain:WWW.Example.COM')).toEqual({ key: 'domain:example.com', domain: 'example.com' });
  });
  it('rejects a bad domain', () => {
    for (const bad of [
      'domain:',
      'domain:localhost',
      'domain:www.com',
      'domain:a b.com',
      'domain:a.com/x',
      'domain:a..com',
      `domain:${'a'.repeat(250)}.com`,
    ])
      expect(hintKey(bad), bad).toBeNull();
  });
  it('ignores anything else', () => {
    for (const other of ['acme', 'name:acme:xx', 'ticker:T', undefined, null, 5])
      expect(hintKey(other)).toBeNull();
  });
});

describe('keys', () => {
  it('jurisdictionCode reads ISO 3166-2 and alpha-2, else xx', () => {
    expect(jurisdictionCode('US-CA')).toBe('us-ca');
    expect(jurisdictionCode(' gb ')).toBe('gb');
    expect(jurisdictionCode('US')).toBe('us');
    for (const bad of ['California', 'USA', 'U', '', 'US-', 'US-CALI', undefined, 7])
      expect(jurisdictionCode(bad)).toBe('xx');
  });

  it('no input escapes the key charset or the length limit', () => {
    const SAFE = /^[a-z0-9:.@-]{1,200}$/;
    const inputs = [
      'Ünïcödé ☃ Corp',
      '../../etc/passwd',
      'a'.repeat(500),
      "Robert'); DROP TABLE companies;--",
      'ＡＢＣ　ｃｏｍｐａｎｙ', // full-width
      '名前 株式会社',
      'x\u0000y\n z',
      '__proto__',
      'A&B',
    ];
    for (const raw of inputs) {
      const norm = normaliseName(raw);
      if (norm === '') continue;
      for (const j of ['us-ca', 'xx', jurisdictionCode(raw)]) expect(nameKey(norm, j), raw).toMatch(SAFE);
    }
    expect(nameKey('a'.repeat(300), 'us-ca')).toHaveLength(5 + 100 + 1 + 5);
    expect(hintKey('cik:7')?.key).toMatch(SAFE);
    expect(hintKey('domain:a-b.example.com')?.key).toMatch(SAFE);
  });
});

describe('spans', () => {
  it('uses the incident dates in order, falling back to discovery then notice', () => {
    expect(
      incidentSpan({ occurredFrom: '2024-02-01', occurredTo: '2024-02-10', notified: '2024-06-01' }),
    ).toEqual({
      from: '2024-02-01',
      to: '2024-02-10',
    });
    expect(incidentSpan({ occurredFrom: '2024-02-01T10:00:00Z' })).toEqual({
      from: '2024-02-01',
      to: '2024-02-01',
    });
    expect(incidentSpan({ discovered: '2024-03-01', notified: '2024-06-01' })).toEqual({
      from: '2024-03-01',
      to: '2024-03-01',
    });
    expect(incidentSpan({ notified: '2024-06-01' })).toEqual({ from: '2024-06-01', to: '2024-06-01' });
  });
  it('swaps an out-of-order span and ignores non-dates', () => {
    expect(incidentSpan({ occurredFrom: '2024-02-10', occurredTo: '2024-02-01' })).toEqual({
      from: '2024-02-01',
      to: '2024-02-10',
    });
    expect(incidentSpan({ occurredFrom: '2024-13-45', discovered: 'soon' })).toBeNull();
    expect(incidentSpan({})).toBeNull();
  });
  it('is close when overlapping or at most 30 days apart', () => {
    const a = { from: '2024-01-01', to: '2024-01-10' };
    expect(spansClose(a, { from: '2024-01-05', to: '2024-01-06' })).toBe(true);
    expect(spansClose(a, { from: '2024-02-09', to: '2024-02-09' })).toBe(true); // gap 30 days
    expect(spansClose(a, { from: '2024-02-10', to: '2024-02-10' })).toBe(false); // gap 31 days
    expect(spansClose({ from: '2024-02-10', to: '2024-02-10' }, a)).toBe(false);
    expect(spansClose(a, { from: '2024-03-01', to: '2024-03-01' }, 60)).toBe(true);
  });
});

describe('companyRow', () => {
  it('builds a row from the first raw name and the hint', () => {
    expect(companyRow('cik:0000732717', ['  AT&T Inc. ', 'AT&T'], undefined, { cik: '0000732717' })).toEqual({
      key: 'cik:0000732717',
      name: 'AT&T Inc.',
      cik: '0000732717',
      domain: null,
      ticker: null,
      sector: null,
      aliases: '["at and t"]',
    });
  });
  it('keeps the stored name, ticker and sector; stored aliases come first', () => {
    const stored = {
      key: 'k',
      name: 'Stored',
      cik: null,
      domain: null,
      ticker: 'T',
      sector: 'telco',
      aliases: '["zeta"]',
    };
    const row = companyRow('k', ['Alpha Inc'], stored, { domain: 'a.com' });
    expect(row).toMatchObject({
      name: 'Stored',
      ticker: 'T',
      sector: 'telco',
      domain: 'a.com',
      aliases: '["zeta","alpha"]',
    });
  });
  it('is null when nothing differs', () => {
    const stored = companyRow('k', ['Alpha Inc'], undefined) as Record<string, unknown>;
    expect(companyRow('k', ['ALPHA'], stored)).toBeNull();
  });
  it('caps the name at 200 and the aliases at 50', () => {
    expect((companyRow('k', ['x'.repeat(300)], undefined) as { name: string }).name).toHaveLength(200);
    const stored = {
      key: 'k',
      name: 'n',
      aliases: JSON.stringify(Array.from({ length: 49 }, (_, i) => `old${i}`)),
    };
    const row = companyRow('k', ['new one', 'new two', 'new three'], stored) as { aliases: string };
    const aliases = JSON.parse(row.aliases) as string[];
    expect(aliases).toHaveLength(50);
    expect(aliases[0]).toBe('old0');
    expect(aliases[49]).toBe('new one');
  });
});
