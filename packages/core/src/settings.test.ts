import { expect, it } from 'vitest';
import { parseSourceSettings, readSourceSettings, sourceSettingsKey, unknownFieldsKey } from './settings';

it('builds keys', () => {
  expect(sourceSettingsKey('nvd')).toBe('source:nvd');
  expect(unknownFieldsKey('nvd')).toBe('unknown-fields:nvd');
});

it('parses valid values', () => {
  expect(parseSourceSettings('{"ingest":false}')).toEqual({ ingest: false });
  expect(parseSourceSettings('{"ingest":true,"display":"link"}')).toEqual({ ingest: true, display: 'link' });
  expect(parseSourceSettings('{}')).toEqual({});
});

it('returns null for missing, bad JSON and wrongly shaped values', () => {
  expect(parseSourceSettings(null)).toBeNull();
  expect(parseSourceSettings('{"ingest":"false"}')).toBeNull();
  expect(parseSourceSettings('not json')).toBeNull();
  expect(parseSourceSettings('{"display":"loud"}')).toBeNull();
  expect(parseSourceSettings('[]')).toBeNull();
  expect(parseSourceSettings('null')).toBeNull();
});

it('ignores unknown keys', () => {
  expect(parseSourceSettings('{"ingest":true,"extra":1}')).toEqual({ ingest: true });
});

it('readSourceSettings reads in chunks of 100 and drops invalid values', async () => {
  const calls: number[] = [];
  const store: Record<string, string> = {
    'source:a': '{"ingest":false}',
    'source:b': 'garbage',
    'source:id150': '{"display":"hidden"}',
  };
  const kv = {
    get: async (keys: string[]) => {
      calls.push(keys.length);
      return new Map(keys.map((k) => [k, store[k] ?? null]));
    },
  } as unknown as KVNamespace;
  const ids = ['a', 'b', ...Array.from({ length: 200 }, (_, i) => `id${i}`)];
  const map = await readSourceSettings(kv, ids);
  expect(calls).toEqual([100, 100, 2]);
  expect(map.get('a')).toEqual({ ingest: false });
  expect(map.has('b')).toBe(false);
  expect(map.get('id150')).toEqual({ display: 'hidden' });
  expect(map.size).toBe(2);
});
