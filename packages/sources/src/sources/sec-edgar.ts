import { src } from '../define';

export default src('sec-edgar', 'SEC EDGAR', '8-K Item 1.05 cyber incidents', 'feed', '3h', 'on', {
  parser: 'sec-edgar',
  pull: {
    feed: {
      url: 'https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent&type=8-K&company=&dateb=&owner=include&start=0&count=100&output=atom',
      order: 'newest-first',
    },
  },
});
