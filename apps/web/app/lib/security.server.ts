// Security headers for every document response; `.data` responses get them minus the CSP.

/** 128 random bits, base64. A new one per request. */
export function makeNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function buildCsp(nonce: string, options: { dev?: boolean } = {}): string {
  // `vite dev` hot reload needs inline preamble scripts (covered by the nonce) and a websocket back to
  // the dev server. Nothing else is relaxed, and production never passes `dev`.
  const scriptSrc = ["'self'", `'nonce-${nonce}'`];
  const connectSrc = ["'self'"];
  if (options.dev) {
    scriptSrc.push("'unsafe-eval'");
    connectSrc.push('ws:', 'http:');
  }
  return [
    "default-src 'self'",
    `script-src ${scriptSrc.join(' ')}`,
    "style-src 'self'",
    "img-src 'self'",
    "font-src 'self'",
    `connect-src ${connectSrc.join(' ')}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
}

export const BASE_HEADERS: Readonly<Record<string, string>> = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  // Each page has its own nonce, so a cached copy would carry a stale one.
  'Cache-Control': 'private, no-cache',
};

/** Search engines must not index sample data or the staging site. */
export function shouldNoindex(sampleData: boolean, tiEnv: string | undefined): boolean {
  return sampleData || tiEnv === 'staging';
}

export function applySecurityHeaders(
  headers: Headers,
  options: { nonce?: string; dev?: boolean; noindex?: boolean },
): void {
  for (const [name, value] of Object.entries(BASE_HEADERS)) headers.set(name, value);
  if (options.nonce) headers.set('Content-Security-Policy', buildCsp(options.nonce, { dev: options.dev }));
  if (options.noindex) headers.set('X-Robots-Tag', 'noindex');
}
