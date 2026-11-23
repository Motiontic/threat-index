import { type OsvProfile, parseOsv } from './osv';

/**
 * OpenSSF malicious-packages. `MAL-0000-<origin>-<hash>` files are temporary placeholders that vanish
 * once an id is allocated; keeping them would leave orphan rows.
 */
const PROFILE: OsvProfile = {
  source: 'openssf-malicious-packages',
  keep: (id) => id.startsWith('MAL-') && !id.startsWith('MAL-0000-'),
};

export function parse(input: unknown) {
  return parseOsv(input, PROFILE);
}
