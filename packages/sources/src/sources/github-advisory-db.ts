import { src } from '../define';

export default src(
  'github-advisory-db',
  'GitHub Advisory DB',
  'Package advisories and malware alerts',
  'git',
  '3h',
  'on',
  {
    credit: 'Source: GitHub Advisory Database (CC BY 4.0)',
    parser: 'osv-ghsa',
    // Reviewed advisories only: unreviewed ones are mostly CVE mirrors with no package data.
    pull: {
      git: {
        repo: 'github/advisory-database',
        branch: 'main',
        include: ['advisories/github-reviewed/**/*.json'],
      },
    },
  },
);
