const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** `7 Apr 2025`, always in UTC and English, so server and browser render the same text. */
export function formatDate(input: string | Date | null | undefined): string {
  if (!input) return '';
  const d = typeof input === 'string' ? new Date(input) : input;
  if (Number.isNaN(d.getTime())) return '';
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

export function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1).trimEnd()}…`;
}

export const TYPE_LABELS = {
  vuln: 'Vulnerability',
  breach: 'Breach',
  ai: 'AI incident',
  mal: 'Malicious package',
  tech: 'Technique',
  term: 'Term',
} as const;

export const TYPE_PLURALS = {
  vuln: 'Vulnerabilities',
  breach: 'Breaches',
  ai: 'AI incidents',
  mal: 'Malicious packages',
  tech: 'Techniques',
  term: 'Terms',
} as const;
