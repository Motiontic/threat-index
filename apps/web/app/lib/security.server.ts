// Security headers for every document response; `.data` responses get them minus the CSP.
import { PRODUCT_SHORT } from '@ti/core/brand';

/** 128 random bits, base64. A new one per request. */
export function makeNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function buildCsp(
  nonce: string,
  options: { dev?: boolean; clerk?: { frontendApi: string } | null } = {},
): string {
  // `vite dev` hot reload needs inline preamble scripts (covered by the nonce) and a websocket back to
  // the dev server. Nothing else is relaxed, and production never passes `dev`.
  const scriptSrc = ["'self'", `'nonce-${nonce}'`];
  const connectSrc = ["'self'"];
  if (options.dev) {
    scriptSrc.push("'unsafe-eval'");
    connectSrc.push('ws:', 'http:');
  }
  const imgSrc = ["'self'"];
  const extra: string[] = [];
  let styleSrc = "style-src 'self'";
  if (options.clerk) {
    // Clerk's widgets add their CSS at run time: <style> elements that carry this request's nonce (the
    // nonce is passed to ClerkProvider) and a few style attributes, which cannot carry one. Without this
    // the sign-in and sign-up forms render unstyled. Stylesheets and <style> still need 'self' or the nonce.
    styleSrc = `style-src 'self' 'nonce-${nonce}'; style-src-elem 'self' 'nonce-${nonce}'; style-src-attr 'unsafe-inline'`;
    // Sign-in widgets: exactly the instance host, Cloudflare's bot challenge and Clerk's avatar host.
    const host = `https://${options.clerk.frontendApi}`;
    scriptSrc.push(host, 'https://challenges.cloudflare.com');
    connectSrc.push(host);
    imgSrc.push('https://img.clerk.com');
    extra.push('frame-src https://challenges.cloudflare.com', "worker-src 'self' blob:");
  }
  return [
    "default-src 'self'",
    `script-src ${scriptSrc.join(' ')}`,
    styleSrc,
    `img-src ${imgSrc.join(' ')}`,
    "font-src 'self'",
    `connect-src ${connectSrc.join(' ')}`,
    ...extra,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
}

export const BASE_HEADERS: Readonly<Record<string, string>> = {
  // No `preload`: that is a domain-wide commitment.
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  // Each page has its own nonce, so a cached copy would carry a stale one.
  'Cache-Control': 'private, no-cache',
};

/**
 * Search engines must not index fixture data, the staging site (it must never compete with production in
 * results), or any error response (status 400 and up).
 */
export function shouldNoindex(input: {
  mode: 'api' | 'fixtures';
  tiEnv: string | undefined;
  status: number;
}): boolean {
  return input.mode === 'fixtures' || input.tiEnv === 'staging' || input.status >= 400;
}

export function applySecurityHeaders(
  headers: Headers,
  options: { nonce?: string; dev?: boolean; noindex?: boolean; clerk?: { frontendApi: string } | null },
): void {
  // A route that asked for `no-store` (/ops) keeps it; every other page gets the base cache header.
  const noStore = /no-store/i.test(headers.get('Cache-Control') ?? '');
  for (const [name, value] of Object.entries(BASE_HEADERS)) {
    if (name === 'Cache-Control' && noStore) continue;
    headers.set(name, value);
  }
  if (options.nonce)
    headers.set(
      'Content-Security-Policy',
      buildCsp(options.nonce, { dev: options.dev, clerk: options.clerk }),
    );
  if (options.noindex) headers.set('X-Robots-Tag', 'noindex');
}

/**
 * Redirects thrown by loaders (the `/e/:id` 301s) skip `handleRequest`, so the worker passes them here.
 * They get the same headers as a document, with their own fresh nonce. Other responses pass through.
 */
export function secureRedirect(
  response: Response,
  options: { dev?: boolean; noindex?: boolean } = {},
): Response {
  if (response.status < 300 || response.status > 399) return response;
  const headers = new Headers(response.headers);
  applySecurityHeaders(headers, { nonce: makeNonce(), dev: options.dev, noindex: options.noindex });
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/** Sets each base header (no CSP) the response lacks. Used for resource routes and the 429 page. */
export function applyMissingBaseHeaders(headers: Headers): void {
  for (const [name, value] of Object.entries(BASE_HEADERS)) if (!headers.has(name)) headers.set(name, value);
}

/** Static page for an over-limit visitor: no script, no external asset. */
export const RATE_LIMITED_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Too many requests · ${PRODUCT_SHORT}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem}</style></head>
<body><h1>Too many requests</h1><p>Too many requests. Wait a minute and try again.</p><p><a href="/">Back to the home page</a></p></body></html>`;

export const RATE_LIMIT_RETRY_AFTER = '60';

/** The 429 for a page request (or a `.data` request, which gets plain text). */
export function rateLimitedResponse(isData: boolean): Response {
  const headers = new Headers({ 'Retry-After': RATE_LIMIT_RETRY_AFTER, 'X-Robots-Tag': 'noindex' });
  headers.set('Cache-Control', 'no-store');
  applyMissingBaseHeaders(headers);
  if (isData) {
    headers.set('Content-Type', 'text/plain; charset=utf-8');
    return new Response('Too many requests', { status: 429, headers });
  }
  headers.set('Content-Type', 'text/html; charset=utf-8');
  headers.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  return new Response(RATE_LIMITED_HTML, { status: 429, headers });
}
