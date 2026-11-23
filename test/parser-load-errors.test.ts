import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

// loadParser imports `./<name>.ts` next to itself. To avoid writing temporary modules into
// packages/parsers/src (which other test files read in parallel), run an exact copy of load.ts from a
// unique temp folder that no other test touches, and put the temporary parsers beside that copy.
const dir = mkdtempSync(join(tmpdir(), 'ti-load-errors-'));
let loadParser: (name: string) => Promise<unknown>;
function tmp(name: string, code: string) {
  writeFileSync(join(dir, `${name}.ts`), code);
}
beforeAll(async () => {
  copyFileSync(new URL('../packages/parsers/src/load.ts', import.meta.url), join(dir, 'load.ts'));
  ({ loadParser } = await import(/* @vite-ignore */ join(dir, 'load.ts')));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('loadParser errors', () => {
  it('reports a missing module as unknown parser', async () => {
    await expect(loadParser('does-not-exist')).rejects.toThrow('unknown parser: does-not-exist');
  });

  it('rethrows a load-time exception with the original error as the cause', async () => {
    tmp('tmp-throws', "throw new Error('boom at load');\nexport const parse = () => [];\n");
    const err = await loadParser('tmp-throws').catch((e) => e);
    expect(err.message).not.toMatch(/unknown parser/);
    expect((err.cause as Error).message).toBe('boom at load');
  });

  it('rethrows a failing import inside an existing parser, not as unknown parser', async () => {
    tmp('tmp-badimport', "import x from './no-such-dependency';\nexport const parse = () => [x];\n");
    const err = await loadParser('tmp-badimport').catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).not.toMatch(/unknown parser/);
    expect(err.cause).toBeDefined();
  });

  it('rethrows a syntax error with the cause', async () => {
    tmp('tmp-syntax', 'export const parse = (;\n');
    const err = await loadParser('tmp-syntax').catch((e) => e);
    expect(err.message).not.toMatch(/unknown parser/);
    expect(err.cause).toBeDefined();
  });
});
