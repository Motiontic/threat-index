import { describe, expect, it } from 'vitest';
import { CAPS, clean } from '../src/clean';
import cases from './fixtures/injection.json';

/** True for any control, hidden, format or markup character. */
function nasty(text: string): boolean {
  for (const ch of text) {
    const c = ch.codePointAt(0) as number;
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f) || (c >= 0x200b && c <= 0x200f)) return true;
    if ((c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069)) return true;
    if (c === 0xfeff || c === 0xad || (c >= 0xfe00 && c <= 0xfe0f) || (c >= 0xe0000 && c <= 0xe01ef))
      return true;
    if (ch === '<' || ch === '>') return true;
  }
  return false;
}

describe('clean', () => {
  it('has at least 30 hostile cases', () => expect(cases.length).toBeGreaterThanOrEqual(30));
  it.each(cases)('$name', ({ input, absent, kept }: { input: string; absent: string[]; kept?: string }) => {
    const out = clean(input, CAPS.summary) ?? '';
    for (const bad of absent) expect(out).not.toContain(bad);
    expect(nasty(out)).toBe(false);
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
