import { type OsvProfile, parseOsv } from './osv';

const PROFILE: OsvProfile = { source: 'debian', keep: (id) => id.startsWith('DEBIAN-CVE-') };

export function parse(input: unknown) {
  return parseOsv(input, PROFILE);
}
