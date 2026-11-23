// Bundles src/run.ts and its @ti/* imports into dist/run.mjs for the E2B template.
// esbuild is not a dependency of this package: it comes with wrangler.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const fromHere = createRequire(import.meta.url);
const fromWrangler = createRequire(fromHere.resolve('wrangler/package.json'));
const { build } = fromWrangler('esbuild');

// `node build.mjs` bundles the runner; `node build.mjs <entry> <outfile>` bundles another script (the bench).
const [entry = 'src/run.ts', out = 'dist/run.mjs'] = process.argv.slice(2);

await build({
  entryPoints: [`${here}${entry}`],
  outfile: `${here}${out}`,
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  logLevel: 'info',
});
