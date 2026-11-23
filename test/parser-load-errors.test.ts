import { rmSync, writeFileSync } from 'node:fs';
import { afterAll, describe, expect, it } from 'vitest';
import { loadParser } from '../packages/parsers/src/load';

const dir = new URL('../packages/parsers/src/', import.meta.url);
const made: URL[] = [];
function tmp(name: string, code: string) {
  const f = new URL(`${name}.ts`, dir);
  writeFileSync(f, code);
  made.push(f);
}
afterAll(() => {
  for (const f of made) rmSync(f, { force: true });
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
