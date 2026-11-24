// The visitor's theme choice lives in a cookie, so the server renders the right theme and nothing flashes.
// With no cookie the page follows `prefers-color-scheme` in CSS.
export type Theme = 'light' | 'dark';
export const THEME_COOKIE = 'ti-theme';
const YEAR = 60 * 60 * 24 * 365;

export function isTheme(value: unknown): value is Theme {
  return value === 'light' || value === 'dark';
}

/** The stored choice from a `Cookie` header, or null when there is none (or it is not a known value). */
export function parseTheme(cookieHeader: string | null | undefined): Theme | null {
  for (const part of (cookieHeader ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== THEME_COOKIE) continue;
    const value = part.slice(eq + 1).trim();
    return isTheme(value) ? value : null;
  }
  return null;
}

/** The `document.cookie` string that stores a choice for a year. */
export function themeCookie(theme: Theme, secure: boolean): string {
  return `${THEME_COOKIE}=${theme}; Path=/; Max-Age=${YEAR}; SameSite=Lax${secure ? '; Secure' : ''}`;
}
