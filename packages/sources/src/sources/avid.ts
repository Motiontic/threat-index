import { src } from '../define';

// AVID's report repo (MIT). `reports/review/` is left out on purpose: those are copies under review. The first
// run hands the repo archive to `first-load`, which does not unpack archives yet, so the backlog waits for that;
// new commits flow from the second run.
export default src('avid', 'AVID', 'AI vulnerability reports', 'git', 'weekly', 'on', {
  parser: 'avid',
  pull: {
    git: {
      repo: 'avidml/avid-db',
      branch: 'main',
      include: ['reports/20*/AVID-*.json', 'vulnerabilities/20*/AVID-*.json'],
    },
  },
});
