import { readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SOURCES } from '../packages/sources/src/registry';

describe('one file per source', () => {
  const dir = new URL('../packages/sources/src/sources/', import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith('.ts'));

  it('has 55 files with 55 unique ids', () => {
    expect(files).toHaveLength(55);
    expect(SOURCES).toHaveLength(55);
    expect(new Set(SOURCES.map((s) => s.id)).size).toBe(55);
  });

  it("names each file after the id it exports, and registry.ts includes every file's source", async () => {
    for (const f of files) {
      const mod = await import(/* @vite-ignore */ `../packages/sources/src/sources/${f}`);
      const id = f.replace(/\.ts$/, '');
      expect(mod.default.id, f).toBe(id);
      expect(SOURCES, id).toContain(mod.default);
    }
  });
});
