import { src } from '../define';

// The server ignores `Range` (always 200, full 4 MB body), so a run sees the newest 256 KB of the list (about
// 4,600 changes); larger bursts hand off a `big-file` job.
export default src('red-hat', 'Red Hat', 'Red Hat fix status', 'changelist', '3h', 'on', {
  credit: 'Source: Red Hat Security Data (CC BY 4.0)',
  parser: 'csaf',
  pull: {
    changelist: {
      listUrl: 'https://security.access.redhat.com/data/csaf/v2/vex/changes.csv',
      timeColumn: 1,
      refColumn: 0,
      itemUrl: 'https://security.access.redhat.com/data/csaf/v2/vex/{ref}',
      rangeBytes: 262_144,
    },
  },
});
