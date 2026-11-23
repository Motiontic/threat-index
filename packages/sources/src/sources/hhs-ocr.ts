import { src } from '../define';

// Pattern is `page`, not `fingerprint`: the HHS CSV/XML exports are JSF postbacks that no pattern can make.
export default src('hhs-ocr', 'HHS OCR', 'US health breaches', 'page', 'daily', 'on', {
  parser: 'hhs-ocr',
  pull: {
    page: {
      url: 'https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf',
      item: 'tbody[id$="reportResultTable_data"] > tr',
      key: 'name',
      order: 'newest-first',
      fields: {
        name: 'td:nth-child(2)',
        state: 'td:nth-child(3)',
        entityType: 'td:nth-child(4)',
        individuals: 'td:nth-child(5)',
        submitted: 'td:nth-child(6)',
        breachType: 'td:nth-child(7)',
        location: 'td:nth-child(8)',
        associate: 'td:nth-child(9)',
      },
    },
  },
});
