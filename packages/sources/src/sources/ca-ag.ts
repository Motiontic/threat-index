import { src } from '../define';

// Pattern is `page`, not `fingerprint`: the CA CSV export has no id or link column, so it can't key notices.
export default src('ca-ag', 'California AG', 'Breach notices', 'page', 'daily', 'ask', {
  parser: 'ca-ag',
  pull: {
    page: {
      url: 'https://oag.ca.gov/privacy/databreach/list',
      item: 'table.views-table > tbody > tr',
      key: 'link',
      order: 'newest-first',
      fields: {
        name: 'td.views-field-field-sb24-org-name > a',
        link: { selector: 'td.views-field-field-sb24-org-name > a', attr: 'href' },
        breachDates: 'td.views-field-field-sb24-breach-date',
        reported: 'td.views-field-created',
      },
    },
  },
});
