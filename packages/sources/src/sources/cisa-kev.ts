import { src } from '../define';

// The official JSON feed (~1.8 MB, one catalogue object). Entries are keyed by `cveID`; each step hands the
// `kev` parser a catalogue that holds only the changed entries. `catalogVersion` is read from the file head,
// so an unchanged catalogue costs one 512-byte ranged read. Shape checked against the live feed on
// 24 Nov 2026 (fixtures/cisa-kev/real-feed.json).
export default src('cisa-kev', 'CISA KEV', 'Exploited in the wild', 'fingerprint', '3h', 'on', {
  parser: 'kev',
  pull: {
    fingerprint: {
      url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      format: 'json',
      itemsPath: 'vulnerabilities',
      key: 'cveID',
      version: { bytes: 512, pattern: '"catalogVersion"\\s*:\\s*"([^"]+)"' },
    },
  },
});
