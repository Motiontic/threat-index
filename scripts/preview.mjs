// Uploads this branch's API as a preview version of the *staging* Worker and prints its URL.
// Loops test against that URL, so nothing heavy runs on the laptop: no local workerd, no local DB.
// The preview shares staging's D1, R2, KV and queues; it does not receive cron or queue events.
//
//   pnpm preview            upload and print the URL
//   pnpm preview --migrate  first apply this branch's pending migrations to the staging databases
import { execFileSync } from 'node:child_process';
import { migrate, wrangler } from './deploy.mjs';
import { loadDotEnv, ROOT, writeDeployConfig } from './wrangler-config.mjs';

loadDotEnv();
const branch = execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
  cwd: ROOT,
  encoding: 'utf8',
}).trim();
const sha = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
const alias = branch
  .replace(/^feat\//, '')
  .toLowerCase()
  .replace(/[^a-z0-9-]+/g, '-')
  .replace(/^-+|-+$/g, '')
  .slice(0, 40);
if (!alias) throw new Error(`cannot make a preview alias from branch "${branch}"`);

const config = writeDeployConfig('api', 'staging');
if (process.argv.includes('--migrate')) migrate('staging', config);

const out = wrangler([
  'versions',
  'upload',
  '--env',
  'staging',
  '-c',
  config,
  '--preview-alias',
  alias,
  '--message',
  `${branch} @ ${sha}`,
]);
const urls = [...out.matchAll(/https:\/\/[^\s]+\.workers\.dev/g)].map((m) => m[0]);
const aliasUrl = urls.find((u) => u.includes(`//${alias}-`)) ?? urls.at(-1);
if (!aliasUrl) {
  process.stdout.write(out);
  throw new Error('no preview URL in the wrangler output');
}
console.log(aliasUrl);
