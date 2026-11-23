import type { EntryType } from './types';

/** `mal` for malicious packages; the API's vulnerability kinds are all `vuln`; other types pass through. */
export function displayType(kind?: string, key?: string): EntryType {
  switch (kind) {
    case 'mal':
      return 'mal';
    case 'cve':
    case 'ghsa':
    case 'osv':
    case 'euvd':
    case 'other':
      return 'vuln';
    case 'breach':
    case 'ai':
    case 'tech':
    case 'term':
      return kind;
  }
  return key?.toUpperCase().startsWith('MAL-') ? 'mal' : 'vuln';
}
