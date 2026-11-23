// Bundles src/run.ts and its @ti/* imports into dist/run.mjs for the E2B template.
// esbuild is not a dependency of this package: it comes with wrangler.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const fromHere = createRequire(import.meta.url);
const fromWrangler = createRequire(fromHere.resolve('wrangler/package.json'));
const { build } = fromWrangler('esbuild');

await build({
  entryPoints: [`${here}src/run.ts`],
  outfile: `${here}dist/run.mjs`,
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  logLevel: 'info',
});
