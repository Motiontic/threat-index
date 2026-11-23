import { src } from '../define';

// BSI's TLP:WHITE CSAF directory lists changes newest first in `changes.csv` (ETag, byte ranges); each ref is one
// CSAF document under the same directory.
export default src('bsi-cert-bund', 'BSI CERT-Bund', 'German advisories', 'changelist', '3h', 'ask', {
  parser: 'cert-bund',
  pull: {
    changelist: {
      listUrl: 'https://wid.cert-bund.de/.well-known/csaf/white/changes.csv',
      timeColumn: 1,
      refColumn: 0,
      itemUrl: 'https://wid.cert-bund.de/.well-known/csaf/white/{ref}',
    },
  },
});
