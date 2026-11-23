import { describe, expect, it } from 'vitest';
import {
  DEEP_TEMPLATES,
  type DeepTemplate,
  MAX_SPAN_DAYS,
  validateDeepQuery,
} from '../../../../apps/api/src/lib/deep-templates.ts';

const NOW = new Date('2026-11-23T10:00:00Z');
const check = (template: unknown, params: unknown, extra: Record<string, unknown> = {}) =>
  validateDeepQuery({ template, params, ...extra }, NOW);

const GOOD: Record<DeepTemplate, Record<string, string>> = {
  'cve-history': { cve: 'cve-2024-12345' },
  'package-advisories': { ecosystem: 'PyPI', package: '@scope/pkg.name_1+x' },
  'epss-history': { cve: 'CVE-2024-0001', from: '2026-11-01', to: '2026-11-22' },
  'company-breaches': { company: 'Acme Corp, Inc.' },
  'kev-additions': { from: '2025-05-01', to: '2025-05-31' },
};

describe('validateDeepQuery', () => {
  it.each(Object.keys(GOOD) as DeepTemplate[])('accepts a good %s', (t) => {
    const r = check(t, GOOD[t]);
    expect(r.ok).toBe(true);
  });

  it('upper-cases the CVE and trims a company', () => {
    const r = check('cve-history', { cve: 'cve-2024-0001' });
    expect(r.ok && r.query.params.cve).toBe('CVE-2024-0001');
    const c = check('company-breaches', { company: '  Acme  ' });
    expect(c.ok && c.query.params.company).toBe('Acme');
  });

  it('accepts cik: and domain: companies', () => {
    expect(check('company-breaches', { company: 'cik:1234567890' }).ok).toBe(true);
    expect(check('company-breaches', { company: 'domain:example.co.uk' }).ok).toBe(true);
    expect(check('company-breaches', { company: 'Müller & Söhne' }).ok).toBe(true);
  });

  const BAD: [string, unknown, string][] = [
    ['cve-history', { cve: "CVE-2024-1' OR 1=1" }, 'cve'],
    ['cve-history', { cve: 'CVE-2024-1234;' }, 'cve'],
    ['cve-history', { cve: 'CVE-2024-1234\n' }, 'cve'],
    ['cve-history', { cve: 'CVE-2024-123' }, 'cve'],
    ['cve-history', { cve: 'CVE-2024-12345678' }, 'cve'],
    ['cve-history', { cve: 5 }, 'cve'],
    ['cve-history', {}, 'cve'],
    ['cve-history', { cve: 'CVE-2024-1234', x: 'y' }, 'x'],
    ['cve-history', { cve: 'CVE-2024-1234', __proto__x: 'y' }, '__proto__x'],
    ['package-advisories', { ecosystem: "PyPI'", package: 'a' }, 'ecosystem'],
    ['package-advisories', { ecosystem: 'PyPI', package: 'a;b' }, 'package'],
    ['package-advisories', { ecosystem: 'PyPI', package: 'a--b b' }, 'package'],
    ['package-advisories', { ecosystem: 'PyPI', package: 'a'.repeat(215) }, 'package'],
    ['package-advisories', { ecosystem: 'P'.repeat(41), package: 'a' }, 'ecosystem'],
    ['package-advisories', { ecosystem: '1PyPI', package: 'a' }, 'ecosystem'],
    ['company-breaches', { company: "x'; DROP TABLE y; --" }, 'company'],
    ['company-breaches', { company: 'domain:Example.com' }, 'company'],
    ['company-breaches', { company: 'domain:nodot' }, 'company'],
    ['company-breaches', { company: 'cik:12345678901' }, 'company'],
    ['company-breaches', { company: 'a' }, 'company'],
    ['company-breaches', { company: 'a'.repeat(81) }, 'company'],
    ['company-breaches', { company: 'line\nbreak' }, 'company'],
    ['epss-history', { cve: 'CVE-2024-0001', from: '2026-02-30' }, 'from'],
    ['epss-history', { cve: 'CVE-2024-0001', from: '2026-11-22', to: '2026-11-01' }, 'from'],
    ['epss-history', { cve: 'CVE-2024-0001', from: '2026-10-01', to: '2026-11-22' }, 'from'],
    ['epss-history', { cve: 'CVE-2024-0001', from: '2026-11-20', to: '2026-11-24' }, 'to'],
    ['epss-history', { cve: 'CVE-2024-0001', to: '2026-11-24' }, 'to'],
    ['epss-history', { cve: 'CVE-2024-0001', from: '2026-11-20', to: '2026-11-22 ' }, 'to'],
    ['kev-additions', { from: '2024-01-01', to: '2025-01-02' }, 'from'],
    ['kev-additions', { from: '20250101' }, 'from'],
    ['kev-additions', { to: '2026-11-24' }, 'to'],
  ];
  it.each(BAD)('refuses %s %j', (t, params, field) => {
    expect(check(t, params)).toEqual({ ok: false, field });
  });

  it('refuses bad bodies', () => {
    expect(check('nope', {})).toEqual({ ok: false, field: 'template' });
    expect(check('__proto__', {})).toEqual({ ok: false, field: 'template' });
    expect(check('constructor', {})).toEqual({ ok: false, field: 'template' });
    expect(check(undefined, {})).toEqual({ ok: false, field: 'template' });
    expect(check('cve-history', undefined)).toEqual({ ok: false, field: 'params' });
    expect(check('cve-history', ['CVE-2024-1234'])).toEqual({ ok: false, field: 'params' });
    expect(check('cve-history', { cve: 'CVE-2024-1234' }, { sql: 'x' })).toEqual({ ok: false, field: 'sql' });
    expect(validateDeepQuery('x')).toEqual({ ok: false, field: 'body' });
    expect(validateDeepQuery(null)).toEqual({ ok: false, field: 'body' });
  });

  it('defaults to and from to the template span, and accepts the exact limit', () => {
    const e = check('epss-history', { cve: 'CVE-2024-0001' });
    expect(e.ok && e.query.params).toEqual({ cve: 'CVE-2024-0001', from: '2026-10-24', to: '2026-11-23' });
    const k = check('kev-additions', {});
    expect(k.ok && k.query.params.to).toBe('2026-11-23');
    expect(k.ok && k.query.params.from).toBe('2025-11-23');
    expect(check('kev-additions', { from: '2025-11-23' }).ok).toBe(true);
    expect(check('kev-additions', { from: '2025-11-22' }).ok).toBe(false);
    expect(MAX_SPAN_DAYS['epss-history']).toBe(31);
  });

  it('has a spec for every template', () => {
    for (const t of Object.keys(GOOD)) expect(DEEP_TEMPLATES[t as DeepTemplate].params).toBeTruthy();
  });
});
