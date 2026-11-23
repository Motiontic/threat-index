import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { formatDate, truncate } from '../app/lib/format';
import { buildMeta, escapeJsonLd, JsonLd, jsonLdString, pageTitle } from '../app/lib/seo';

describe('JSON-LD', () => {
  it('escapes <, >, & and the two line separators', () => {
    const out = escapeJsonLd(`<>&  `);
    expect(out).toBe('\\u003c\\u003e\\u0026\\u2028\\u2029');
  });

  it('keeps a </script> title inert and the JSON round-trippable', () => {
    const title = '</script><script>alert(1)</script> & more ';
    const html = renderToStaticMarkup(<JsonLd nonce="n" data={{ name: title }} />);
    expect(html.match(/<script/g)).toHaveLength(1);
    expect(html.match(/<\/script>/g)).toHaveLength(1);
    expect(html).not.toContain('alert(1)</script>');
    const body = html.replace(/^<script[^>]*>/, '').replace(/<\/script>$/, '');
    expect(JSON.parse(body).name).toBe(title);
    expect(jsonLdString({ a: '<' })).not.toContain('<');
  });
});

describe('meta', () => {
  const meta = buildMeta({
    title: pageTitle('CVE-2025-3248: Langflow unauthenticated code execution'),
    description: 'x'.repeat(400),
    path: '/e/CVE-2025-3248',
    origin: 'https://threatindex.example',
  });
  const get = (k: string, v: string) => meta.find((m) => m[k] === v);

  it('has the title, description, Open Graph tags and a canonical from the request origin', () => {
    expect(meta[0]).toEqual({
      title: 'CVE-2025-3248: Langflow unauthenticated code execution · Threat Index',
    });
    expect(get('name', 'description')?.content).toHaveLength(160);
    expect(get('property', 'og:title')).toBeDefined();
    expect(get('property', 'og:description')?.content).toHaveLength(160);
    expect(get('property', 'og:type')).toBeDefined();
    expect(get('property', 'og:url')?.content).toBe('https://threatindex.example/e/CVE-2025-3248');
    expect(get('rel', 'canonical')?.href).toBe('https://threatindex.example/e/CVE-2025-3248');
  });

  it('adds noindex only when asked', () => {
    expect(get('name', 'robots')).toBeUndefined();
    const noindex = buildMeta({
      title: 't',
      description: 'd',
      path: '/search',
      origin: 'https://a.test',
      noindex: true,
    });
    expect(noindex.find((m) => m.name === 'robots')?.content).toBe('noindex');
  });

  it('cuts text at the limit with an ellipsis', () => {
    expect(truncate('short', 10)).toBe('short');
    expect(truncate('abcdefghij', 5)).toBe('abcd…');
  });
});

describe('date formatter', () => {
  it('formats in UTC, English, day month year', () => {
    expect(formatDate('2025-04-07')).toBe('7 Apr 2025');
    expect(formatDate('2025-12-31T23:59:59Z')).toBe('31 Dec 2025');
    expect(formatDate('2026-01-01T00:00:00Z')).toBe('1 Jan 2026');
    expect(formatDate(new Date(Date.UTC(2021, 11, 10)))).toBe('10 Dec 2021');
  });

  it('gives an empty string for nothing or nonsense', () => {
    expect(formatDate(null)).toBe('');
    expect(formatDate('not a date')).toBe('');
  });
});
