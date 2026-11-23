import { src } from '../define';

export default src('debian', 'Debian', 'Debian fix status (through OSV)', 'changelist', '3h', 'ask', {
  parser: 'osv-debian',
  pull: {
    changelist: {
      listUrl: 'https://osv-vulnerabilities.storage.googleapis.com/Debian/modified_id.csv',
      timeColumn: 0,
      refColumn: 1,
      itemUrl: 'https://osv-vulnerabilities.storage.googleapis.com/Debian/{ref}.json',
    },
  },
});
