import { src } from '../define';

export default src('ubuntu', 'Ubuntu', 'Ubuntu fix status (through OSV)', 'changelist', '3h', 'ask', {
  parser: 'osv-ubuntu',
  pull: {
    changelist: {
      listUrl: 'https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/modified_id.csv',
      timeColumn: 0,
      refColumn: 1,
      itemUrl: 'https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/{ref}.json',
    },
  },
});
