import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { INTENT_KEY, MAX_INTENT_AGE_MS, MAX_INTENT_CHARS, saveIntent, takeIntent } from '../app/lib/intent';

function stubStorage(overrides: Partial<Storage> = {}) {
  const map = new Map<string, string>();
  const storage = {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    ...overrides,
  };
  vi.stubGlobal('sessionStorage', storage);
  return map;
}

let map: Map<string, string>;
beforeEach(() => {
  map = stubStorage();
});
afterEach(() => vi.unstubAllGlobals());

describe('intent', () => {
  it('round-trips each action and clears on take', () => {
    for (const intent of [
      { action: 'watch', target: 'CVE-2025-1' },
      { action: 'save-search', target: '?q=log4j&sig=kev' },
      { action: 'tab', target: 'CVE-2025-1#evidence' },
    ] as const) {
      saveIntent(intent, 1000);
      expect(takeIntent(2000)).toEqual({ ...intent, at: 1000 });
      expect(takeIntent(2000)).toBeNull();
    }
  });

  it('expires after 30 minutes but not before', () => {
    saveIntent({ action: 'watch', target: 'CVE-1' }, 0);
    expect(takeIntent(MAX_INTENT_AGE_MS)).not.toBeNull();
    saveIntent({ action: 'watch', target: 'CVE-1' }, 0);
    expect(takeIntent(MAX_INTENT_AGE_MS + 1)).toBeNull();
  });

  it('clears an intent even when it is rejected', () => {
    map.set(INTENT_KEY, '{"action":"nope","target":"x","at":1}');
    expect(takeIntent(2)).toBeNull();
    expect(map.has(INTENT_KEY)).toBe(false);
  });

  it('rejects bad shapes', () => {
    const at = 1000;
    for (const bad of [
      'not json',
      'null',
      '[]',
      '"x"',
      JSON.stringify({ action: 'watch', target: 'CVE-1' }), // no at
      JSON.stringify({ action: 'watch', target: 'CVE-1', at: 'now' }),
      JSON.stringify({ action: 'watch', target: '', at }),
      JSON.stringify({ action: 'watch', target: 5, at }),
      JSON.stringify({ action: 'delete', target: 'CVE-1', at }),
      JSON.stringify({ action: 'watch', target: 'bad id!', at }),
      JSON.stringify({ action: 'tab', target: 'CVE-1', at }),
      JSON.stringify({ action: 'tab', target: 'CVE-1#Evidence?x', at }),
      JSON.stringify({ action: 'watch', target: 'CVE-1', at: 10 ** 12 }), // from the far future
    ]) {
      map.set(INTENT_KEY, bad);
      expect(takeIntent(at + 5), bad).toBeNull();
    }
  });

  it('rejects a value longer than 600 characters, and refuses to store one', () => {
    map.set(
      INTENT_KEY,
      JSON.stringify({ action: 'save-search', target: 'a'.repeat(MAX_INTENT_CHARS), at: 1 }),
    );
    expect(takeIntent(2)).toBeNull();
    saveIntent({ action: 'save-search', target: 'a'.repeat(MAX_INTENT_CHARS) }, 1);
    expect(map.has(INTENT_KEY)).toBe(false);
  });

  it('swallows storage errors on save and on take', () => {
    stubStorage({
      setItem: () => {
        throw new Error('quota');
      },
      getItem: () => {
        throw new Error('denied');
      },
    });
    expect(() => saveIntent({ action: 'watch', target: 'CVE-1' })).not.toThrow();
    expect(takeIntent()).toBeNull();
    vi.stubGlobal('sessionStorage', undefined);
    expect(() => saveIntent({ action: 'watch', target: 'CVE-1' })).not.toThrow();
    expect(takeIntent()).toBeNull();
  });
});
