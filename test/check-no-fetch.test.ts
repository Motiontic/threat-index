import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs script without types
import { findViolations, RULES } from '../scripts/check-no-fetch.mjs';

const roots: string[] = [];
function repoWith(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'no-fetch-'));
  roots.push(root);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}
afterEach(() => {
  for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
});

describe('check-no-fetch', () => {
  it('passes on the real repo', () => {
    expect(findViolations()).toEqual([]);
  });

  it('fails on a planted fetch( in apps/mcp/src/tools', () => {
    const root = repoWith({
      'apps/mcp/src/api.ts':
        'export const ok = (env) => env.API.fetch(new Request("https://ti-api.internal/"));',
      'apps/mcp/src/tools/mti_search.ts': 'export async function run(u: string) {\n  return fetch(u);\n}\n',
    });
    expect(findViolations(root)).toEqual([{ file: 'apps/mcp/src/tools/mti_search.ts', line: 2 }]);
  });

  it('catches globalThis.fetch( and env.X.fetch( outside api.ts, and spaced calls', () => {
    const root = repoWith({
      'apps/mcp/src/a.ts': 'globalThis.fetch(u);',
      'apps/mcp/src/b.ts': 'env.API.fetch (req);',
      'apps/mcp/src/c.ts': 'await fetch\n(u);\nawait fetch(u)',
    });
    expect(
      findViolations(root)
        .map((v: { file: string }) => v.file)
        .sort(),
    ).toEqual(['apps/mcp/src/a.ts', 'apps/mcp/src/b.ts', 'apps/mcp/src/c.ts']);
  });

  it('allows api.ts in apps/mcp and the listed files in apps/api, but not other api files', () => {
    const root = repoWith({
      'apps/mcp/src/api.ts': 'fetch(u)',
      'apps/api/src/lib/clerk-api.ts': 'globalThis.fetch(u)',
      'apps/api/src/routes/new.ts': 'fetch(u)',
    });
    expect(findViolations(root)).toEqual([{ file: 'apps/api/src/routes/new.ts', line: 1 }]);
  });

  it('ignores handler definitions and comments', () => {
    const root = repoWith({
      'apps/mcp/src/index.ts':
        'export default {\n  async fetch(request) {},\n};\n// fetch(url) is not allowed\n/* fetch(url) */\n',
      'apps/mcp/src/tasks/t.ts': 'class T {\n  override async fetch(r) {}\n}\n',
    });
    expect(findViolations(root)).toEqual([]);
  });

  it('lists the allowed files in the script', () => {
    expect(RULES).toEqual([
      { dir: 'apps/mcp/src', allowed: ['api.ts', 'auth/jwks.ts'] },
      { dir: 'apps/api/src', allowed: ['lib/clerk-api.ts'] },
    ]);
  });
});
