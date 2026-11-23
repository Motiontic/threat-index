import { src } from '../define';

// The global modified_id.csv changes faster than four 64 KB ranges cover in three hours, so most runs hand
// off to E2B as `big-file` until a per-ecosystem fan-out exists. That is expected, not an error.
export default src('osv', 'OSV.dev', 'Affected package versions', 'changelist', '3h', 'on', {
  parser: 'osv',
  pull: {
    changelist: {
      listUrl: 'https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv',
      timeColumn: 0,
      refColumn: 1,
      itemUrl: 'https://osv-vulnerabilities.storage.googleapis.com/{ref}.json',
    },
  },
});
