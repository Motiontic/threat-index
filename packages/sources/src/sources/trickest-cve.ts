import { src } from '../define';

// Steady-state pulls only: each run reads the files changed since the stored commit. The
// repository archive a first run hands to a job is unpacked by the first-load job, not here.
export default src(
  'trickest-cve',
  'trickest/cve',
  'Proof-of-concept links (weak signal)',
  'git',
  'daily',
  'on',
  {
    parser: 'trickest-cve',
    pull: { git: { repo: 'trickest/cve', branch: 'main', include: ['*/CVE-*.md'] } },
  },
);
