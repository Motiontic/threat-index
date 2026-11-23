// @ts-nocheck: uses node:fs and node:path, which this app's tsconfig has no types for.
// Vitest returns an empty string for `?raw` CSS imports, so tests read source files from disk instead.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const WEB_DIR = fileURLToPath(new URL('..', import.meta.url));

export function readWeb(path: string): string {
  return readFileSync(join(WEB_DIR, path), 'utf8');
}

/** Every .ts, .tsx and .css file under apps/web/app, as [path relative to apps/web, text]. */
export function appFiles(): (readonly [string, string])[] {
  const walk = (dir: string): string[] =>
    readdirSync(dir).flatMap((f) => {
      const p = join(dir, f);
      return statSync(p).isDirectory() ? walk(p) : [p];
    });
  return walk(join(WEB_DIR, 'app'))
    .filter((p) => /\.(tsx?|css)$/.test(p) && !p.endsWith('.d.ts'))
    .map((p) => [relative(WEB_DIR, p).split('\\').join('/'), readFileSync(p, 'utf8')] as const);
}
