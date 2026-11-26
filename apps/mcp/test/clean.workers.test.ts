import { describe, expect, it } from 'vitest';
import { CAPS, clean } from '../src/clean';
import cases from './fixtures/injection.json';

// biome-ignore lint/suspicious/noControlCharactersInRegex: the point of the test
const NASTY = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿­︀-️<>]|[\u{E0000}-\u{E01EF}]/u;

describe('clean', () => {
  it('has at least 30 hostile cases', () => expect(cases.length).toBeGreaterThanOrEqual(30));
  it.each(cases)('$name', ({ input, absent, kept }: { input: string; absent: string[]; kept?: string }) => {
    const out = clean(input, CAPS.summary) ?? '';
    for (const bad of absent) expect(out).not.toContain(bad);
    expect(out).not.toMatch(NASTY);
    expect(out).not.toMatch(/https?:\/\//i);
    if (kept) expect(out).toContain(kept);
  });
  it('caps 10,000 characters at 600 with an ellipsis', () => {
    const out = clean('word '.repeat(2000), 600) as string;
    expect([...out].length).toBe(600);
    expect(out.endsWith('…')).toBe(true);
  });
  it('never splits a surrogate pair at the cap', () => {
    const out = clean(`${'a'.repeat(8)}😀😀😀`, 10) as string;
    expect(out).toBe(`${'a'.repeat(8)}😀…`);
    expect(/[\ud800-\udbff](?![\udc00-\udfff])/.test(out)).toBe(false);
  });
  it('returns null for non-strings and empty results', () => {
    expect(clean(5, 10)).toBeNull();
    expect(clean(null, 10)).toBeNull();
    expect(clean('​\u001b[0m  ', 10)).toBeNull();
  });
});
