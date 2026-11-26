import { normaliseId } from '@ti/core/ids';

export type InputProblem = 'bad_characters' | 'not_an_id' | 'looks_like_email';

// biome-ignore lint/suspicious/noControlCharactersInRegex: detecting controls is the point
const BAD = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\p{Cf}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}\u{E0000}-\u{E007F}]/u;

/** True for C0/C1 controls, format characters (zero-width, bidi, Tags) and variation selectors. */
export function hasBadText(value: string): boolean {
  return BAD.test(value);
}

/** JSON path of the first string holding bad text, such as "packages[3].name". Never the value. */
export function findBadText(args: unknown, path = ''): string | null {
  if (typeof args === 'string') return hasBadText(args) ? path || '$' : null;
  if (Array.isArray(args)) {
    for (let i = 0; i < args.length; i++) {
      const hit = findBadText(args[i], `${path}[${i}]`);
      if (hit) return hit;
    }
    return null;
  }
  if (args && typeof args === 'object') {
    for (const [k, v] of Object.entries(args)) {
      if (hasBadText(k)) return path || '$';
      const hit = findBadText(v, path ? `${path}.${k}` : k);
      if (hit) return hit;
    }
  }
  return null;
}

export const ENTRY_ID =
  /^(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|(?:PYSEC|GO|OSV|MAL|EUVD)-\d{4}-\d{1,7}|RUSTSEC-\d{4}-\d{4}|RHSA-\d{4}:\d{1,6}|USN-\d{1,5}(?:-\d{1,2})?|DSA-\d{1,5}(?:-\d{1,2})?|DLA-\d{1,5}(?:-\d{1,2})?|JVNDB-\d{4}-\d{1,7})$/;
export const TECHNIQUE_ID = /^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?|CWE-\d{1,6}|CAPEC-\d{1,6})$/;

/** NFKC, trim, and the API's own ID normalisation. */
export function normaliseEntryId(raw: string): string {
  return normaliseId(raw.normalize('NFKC').trim());
}
