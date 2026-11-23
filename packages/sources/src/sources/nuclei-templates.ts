import { src } from '../define';

export default src('nuclei-templates', 'Nuclei templates', 'A scanner can detect it', 'git', '3h', 'on', {
  parser: 'nuclei',
  pull: {
    git: { repo: 'projectdiscovery/nuclei-templates', branch: 'main', include: ['**/cves/**/*.yaml'] },
  },
});
