import { src } from '../define';

// Cisco's public CSAF directory is used because the openVuln API needs OAuth. The whole list (about 178 KB)
// fits one read; the server ignores `Range`.
export default src('cisco', 'Cisco', 'Cisco advisories', 'changelist', '3h', 'ask', {
  parser: 'csaf',
  pull: {
    changelist: {
      listUrl: 'https://www.cisco.com/.well-known/csaf/changes.csv',
      timeColumn: 1,
      refColumn: 0,
      itemUrl: 'https://www.cisco.com/.well-known/csaf/{ref}',
      rangeBytes: 262_144,
    },
  },
});
