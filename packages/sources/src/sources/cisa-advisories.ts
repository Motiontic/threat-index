import { src } from '../define';

export default src('cisa-advisories', 'CISA advisories', 'Government alerts', 'feed', '3h', 'on', {
  parser: 'cisa-advisories',
  pull: { feed: { url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', order: 'newest-first' } },
});
