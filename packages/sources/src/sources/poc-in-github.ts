import { src } from '../define';

export default src(
  'poc-in-github',
  'PoC-in-GitHub',
  'Proof-of-concept repos (weak signal)',
  'git',
  '3h',
  'on',
  {
    parser: 'poc-in-github',
    pull: { git: { repo: 'nomi-sec/PoC-in-GitHub', branch: 'master', include: ['*/CVE-*.json'] } },
  },
);
