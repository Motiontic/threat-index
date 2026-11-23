import { type OsvProfile, parseOsv } from './osv';

const PROFILE: OsvProfile = { source: 'github-advisory-db', keep: (id) => id.startsWith('GHSA-') };

export function parse(input: unknown) {
  return parseOsv(input, PROFILE);
}
