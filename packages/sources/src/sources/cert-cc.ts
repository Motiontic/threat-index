import { src } from '../define';

// The Atom feed has the 15 newest notes by first publication and the note API has no modified-since or offset query,
// so the pattern is `feed`. An update to a note older than the feed's 15 is not picked up.
export default src('cert-cc', 'CERT/CC', 'Vendor affected or not', 'feed', 'daily', 'ask', {
  parser: 'cert-cc',
  pull: { feed: { url: 'https://kb.cert.org/vuls/atomfeed/' } },
});
