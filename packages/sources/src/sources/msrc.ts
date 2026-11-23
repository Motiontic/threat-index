import { src } from '../define';

// The list has no validator and HEAD answers 404, so every daily run reads the head of the list.
export default src('msrc', 'Microsoft MSRC', 'Patch Tuesday fixes', 'changelist', 'daily', 'ask', {
  parser: 'csaf',
  pull: {
    changelist: {
      listUrl: 'https://msrc.microsoft.com/csaf/advisories/changes.csv',
      timeColumn: 1,
      refColumn: 0,
      itemUrl: 'https://msrc.microsoft.com/csaf/advisories/{ref}',
    },
  },
  rateLimit: { perMinute: 60 },
});
