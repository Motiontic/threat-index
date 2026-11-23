import { src } from '../define';

// The "Incidents" tab (gid=888071280) of the AIAAIC sheet. Row 1 is a banner, so `range=A2:T` starts the export at
// the header row. The export is about 966 KB with 2,259 incidents; the fingerprint pattern returns at most 40
// changed rows per step, so the first run walks about 57 steps.
export default src('aiaaic', 'AIAAIC', 'AI incidents and controversies', 'fingerprint', 'weekly', 'ask', {
  parser: 'aiaaic',
  pull: {
    fingerprint: {
      url: 'https://docs.google.com/spreadsheets/d/1Bn55B4xz21-_Rgdr8BBb2lt0n_4rzLGxFADMlVW0PYI/export?format=csv&gid=888071280&range=A2:T',
      format: 'csv',
      key: 'AIAAIC ID#',
    },
  },
});
