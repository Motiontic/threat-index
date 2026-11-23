import { describe, expect, it } from 'vitest';
import {
  applySecurityHeaders,
  BASE_HEADERS,
  buildCsp,
  makeNonce,
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
  it('applies to sample data and to staging', () => {
    expect(shouldNoindex(true, 'production')).toBe(true);
    expect(shouldNoindex(false, 'staging')).toBe(true);
    expect(shouldNoindex(true, undefined)).toBe(true);
    expect(shouldNoindex(false, 'production')).toBe(false);
    expect(shouldNoindex(false, undefined)).toBe(false);
  });
});
