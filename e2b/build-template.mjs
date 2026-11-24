// Builds the E2B template. Run by a person, never by a loop:
//   E2B_API_KEY=… node e2b/build-template.mjs <template-name>
// The `e2b` SDK is loaded from apps/api, where it is a dependency.
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

if (process.env.TI_LOOP_SANDBOX === '1') {
  console.error('build-template: refusing to run inside a loop sandbox');
  process.exit(1);
}
const apiKey = process.env.E2B_API_KEY;
if (!apiKey) {
  console.error('build-template: set E2B_API_KEY');
  process.exit(1);
}
const name = process.argv[2];
if (!name || !/^[a-z0-9][a-z0-9._-]*$/i.test(name)) {
  console.error('usage: E2B_API_KEY=… node e2b/build-template.mjs <template-name>');
  process.exit(2);
}

const root = fileURLToPath(new URL('..', import.meta.url));
execFileSync('pnpm', ['--filter', '@ti/e2b-jobs', 'bundle'], { cwd: root, stdio: 'inherit' });

const { Template, defaultBuildLogger } = createRequire(`${root}apps/api/package.json`)('e2b');
const template = Template({ fileContextPath: `${root}e2b` }).fromDockerfile(
  fileURLToPath(new URL('./e2b.Dockerfile', import.meta.url)),
);
await Template.build(template, name, {
  apiKey,
  cpuCount: 2,
  memoryMB: 4096, // JOB_HEAP_MB (e2b/jobs/src/launch.ts) stays below this, leaving room for DuckDB and the OS
  onBuildLogs: defaultBuildLogger(),
});
console.log(`built template ${name}`);
