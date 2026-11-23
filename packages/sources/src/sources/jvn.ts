import { src } from '../define';

// The iPedia "Update Entry" RDF is about 1.4 MB (500 items), over what a Worker step should parse, so the E2B first-load
// job parses it. The server sends an ETag, so there is no `version` block.
export default src('jvn', 'JVN', 'Japanese vendor advisories', 'heavy', 'daily', 'ask', {
  heavy: true,
  parser: 'jvn',
  pull: { heavy: { url: 'https://jvndb.jvn.jp/en/rss/jvndb.rdf' }, jobKind: 'first-load' },
});
