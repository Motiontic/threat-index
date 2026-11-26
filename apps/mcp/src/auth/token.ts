const B64TOKEN = /^[A-Za-z0-9\-._~+/]+=*$/;
const MAX_TOKEN_CHARS = 8192;

/** Reads the bearer token from the Authorization header only. */
export function bearerFrom(
  request: Request,
): { kind: 'none' } | { kind: 'malformed' } | { kind: 'token'; token: string } {
  const header = request.headers.get('authorization');
  if (header === null) return { kind: 'none' };
  const sp = header.indexOf(' ');
  const scheme = sp < 0 ? header : header.slice(0, sp);
  if (scheme.toLowerCase() !== 'bearer') return { kind: 'none' };
  const value = sp < 0 ? '' : header.slice(sp + 1);
  if (value === '' || value.length > MAX_TOKEN_CHARS || /[,\s]/.test(value))
    return { kind: 'malformed' };
  if (!B64TOKEN.test(value)) return { kind: 'malformed' };
  return { kind: 'token', token: value };
}
