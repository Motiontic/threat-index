import { describe, expect, it } from 'vitest';
import {
  applySecurityHeaders,
  BASE_HEADERS,
  buildCsp,
  makeNonce,
  secureRedirect,
  shouldNoindex,
} from '../app/lib/security.server';

describe('nonce', () => {
  it('is 128 bits of base64 and fresh each time', () => {
    const nonces = new Set(Array.from({ length: 50 }, makeNonce));
    expect(nonces.size).toBe(50);
    for (const n of nonces) {
      expect(n).toMatch(/^[A-Za-z0-9+/]{22}==$/);
      expect(atob(n)).toHaveLength(16);
    }
  });
});

describe('Content-Security-Policy', () => {
  it('is exactly the production policy', () => {
    expect(buildCsp('abc')).toBe(
      "default-src 'self'; script-src 'self' 'nonce-abc'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    );
  });

  it('allows no inline styles, data: URLs, eval or remote origins in production', () => {
    const csp = buildCsp('abc');
    expect(csp).not.toMatch(/unsafe-|data:|https?:|ws:|\*/);
  });

  it('relaxes only script-src and connect-src for vite dev', () => {
    const prod = buildCsp('abc').split('; ');
    const dev = buildCsp('abc', { dev: true }).split('; ');
    const differing = dev.filter((d) => !prod.includes(d)).map((d) => d.split(' ')[0]);
    expect(differing.sort()).toEqual(['connect-src', 'script-src']);
    expect(dev.join('; ')).toContain("'unsafe-eval'");
  });
});

describe('response headers', () => {
  it('sets every header from the spec on a document', () => {
    const h = new Headers();
    applySecurityHeaders(h, { nonce: 'n', noindex: true });
    expect(h.get('Content-Security-Policy')).toContain("'nonce-n'");
    expect(h.get('X-Content-Type-Options')).toBe('nosniff');
    expect(h.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    expect(h.get('X-Frame-Options')).toBe('DENY');
    expect(h.get('Cross-Origin-Opener-Policy')).toBe('same-origin');
    expect(h.get('Permissions-Policy')).toBe('camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    expect(h.get('Cache-Control')).toBe('private, no-cache');
    expect(h.get('X-Robots-Tag')).toBe('noindex');
  });

  it('gives .data responses the same headers minus the CSP', () => {
    const h = new Headers();
    applySecurityHeaders(h, {});
    for (const name of Object.keys(BASE_HEADERS)) expect(h.has(name), name).toBe(true);
    expect(h.has('Content-Security-Policy')).toBe(false);
    expect(h.has('X-Robots-Tag')).toBe(false);
  });
});

describe('noindex rule', () => {
  it('is true for fixtures mode, staging and any status of 400 or more', () => {
    for (const mode of ['api', 'fixtures'] as const) {
      for (const tiEnv of ['production', 'staging', undefined]) {
        for (const status of [200, 301, 399, 400, 404, 502]) {
          const expected = mode === 'fixtures' || tiEnv === 'staging' || status >= 400;
          expect(shouldNoindex({ mode, tiEnv, status }), `${mode} ${tiEnv} ${status}`).toBe(expected);
        }
      }
    }
    expect(shouldNoindex({ mode: 'api', tiEnv: 'production', status: 200 })).toBe(false);
  });
});

describe('redirects', () => {
  it('carry the document headers, a fresh CSP nonce and noindex', () => {
    const a = secureRedirect(new Response(null, { status: 301, headers: { Location: '/e/X' } }), {
      noindex: true,
    });
    const b = secureRedirect(new Response(null, { status: 301, headers: { Location: '/e/X' } }), {
      noindex: true,
    });
    expect(a.status).toBe(301);
    expect(a.headers.get('Location')).toBe('/e/X');
    for (const name of Object.keys(BASE_HEADERS)) expect(a.headers.get(name), name).toBe(BASE_HEADERS[name]);
    expect(a.headers.get('X-Robots-Tag')).toBe('noindex');
    expect(a.headers.get('Content-Security-Policy')).toMatch(
      /^default-src 'self'; script-src 'self' 'nonce-/,
    );
    expect(a.headers.get('Content-Security-Policy')).not.toBe(b.headers.get('Content-Security-Policy'));
  });

  it('leaves non-redirect responses alone', () => {
    const res = new Response('ok', { status: 200 });
    expect(secureRedirect(res, { noindex: true })).toBe(res);
  });
});
