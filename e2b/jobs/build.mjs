// Bundles src/run.ts and its @ti/* imports into dist/run.mjs for the E2B template.
// esbuild is not a dependency of this package: it comes with wrangler.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const fromHere = createRequire(import.meta.url);
const fromWrangler = createRequire(fromHere.resolve('wrangler/package.json'));
const { build } = fromWrangler('esbuild');

// `node build.mjs` bundles the runner; `node build.mjs <entry> <outfile>` bundles another script (the bench).
// With no arguments it also bundles launch.ts (the process the template starts, which runs run.mjs).
const [entry, out] = process.argv.slice(2);
const target = entry
  ? { entryPoints: [`${here}${entry}`], outfile: `${here}${out}` }
  : {
      entryPoints: [`${here}src/run.ts`, `${here}src/launch.ts`],
      outdir: `${here}dist`,
      outExtension: { '.js': '.mjs' },
    };

await build({
  ...target,
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  logLevel: 'info',
});
