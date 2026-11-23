import { src } from '../define';

export default src(
  'openssf-malicious-packages',
  'OpenSSF malicious packages',
  'Poisoned packages',
  'git',
  '3h',
  'on',
  {
    credit: 'Source: OpenSSF Malicious Packages (Apache-2.0)',
    parser: 'osv-malicious',
    pull: {
      git: {
        repo: 'ossf/malicious-packages',
        branch: 'main',
        include: ['osv/malicious/**/*.json', 'osv/withdrawn/**/*.json'],
      },
    },
  },
);
