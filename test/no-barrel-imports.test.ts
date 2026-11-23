import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = new URL('..', import.meta.url).pathname;
const SKIP = new Set(['node_modules', '.wrangler', 'dist', 'worktrees', '.loops', '.git', 'fixtures']);

function* walk(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (/\.(ts|tsx|mjs|js)$/.test(name)) yield p;
  }
}

describe('subpath imports', () => {
  it('never imports a bare @ti/<pkg>; use @ti/<pkg>/<module>', () => {
    const bare = /(?:from|import)\s*\(?\s*['"]@ti\/[a-z0-9-]+['"]/;
    const offenders = ['apps', 'packages', 'e2b']
      .flatMap((d) => [...walk(join(ROOT, d))])
      .filter((f) => bare.test(readFileSync(f, 'utf8')));
    expect(offenders).toEqual([]);
  });

  it('keeps packages free of src/index.ts barrels', () => {
    const barrels = readdirSync(join(ROOT, 'packages')).filter((p) => {
      try {
        statSync(join(ROOT, 'packages', p, 'src', 'index.ts'));
        return true;
      } catch {
        return false;
      }
    });
    expect(barrels).toEqual([]);
  });
});
