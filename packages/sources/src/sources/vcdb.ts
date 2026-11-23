import { src } from '../define';

// The first run hands off a `first-load` job, which loads nothing until that E2B job exists.
export default src('vcdb', 'VCDB (VERIS)', 'Coded breach incidents', 'git', 'daily', 'ask', {
  credit: 'Source: VERIS Community Database (vz-risk/VCDB, CC BY-SA 4.0)',
  parser: 'vcdb',
  pull: {
    git: {
      repo: 'vz-risk/VCDB',
      branch: 'master',
      include: ['data/json/validated/*.json', 'data/json/submitted/*.json'],
    },
  },
});
