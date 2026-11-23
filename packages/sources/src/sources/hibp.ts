import { src } from '../define';

// The server sends no validator, so each run downloads the ~1.1 MB list and diffs it by `Name`; the first run
// spreads ~1,000 changed entries over about 25 steps.
export default src('hibp', 'Have I Been Pwned', 'Verified breached datasets', 'fingerprint', '3h', 'on', {
  credit: 'Source: Have I Been Pwned (haveibeenpwned.com, CC BY 4.0)',
  parser: 'hibp',
  pull: { fingerprint: { url: 'https://haveibeenpwned.com/api/v3/breaches', format: 'json', key: 'Name' } },
});
