import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { loadParser } from '../src/load';

describe('loadParser', () => {
  it("loads the parser a source names: cisa-kev -> 'kev'", async () => {
    const name = SOURCE_BY_ID.get('cisa-kev')?.parser;
    expect(name).toBe('kev');
    const parser = await loadParser(name as string);
    expect(typeof parser.parse).toBe('function');
  });

  it('rejects unknown and malformed names', async () => {
    await expect(loadParser('nope')).rejects.toThrow('unknown parser');
    await expect(loadParser('../core/ids')).rejects.toThrow('invalid parser name');
  });
});
