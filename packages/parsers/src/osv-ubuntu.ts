import { type OsvProfile, parseOsv } from './osv';

const PROFILE: OsvProfile = { source: 'ubuntu', keep: (id) => id.startsWith('UBUNTU-CVE-') };

export function parse(input: unknown) {
  return parseOsv(input, PROFILE);
}
