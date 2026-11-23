import { src } from '../define';

// No parser, no pull. The data is a Google Sheet whose ID changes with each release, so no URL stays stable, and
// its rows are risk statements taken from papers, not incidents. The incident tracker is an Airtable embed with no
// export. See fixtures/mit-ai-risk/SOURCE.md.
export default src('mit-ai-risk', 'MIT AI Risk Repository', 'AI risk categories', 'heavy', 'monthly', 'on', {
  heavy: true,
});
