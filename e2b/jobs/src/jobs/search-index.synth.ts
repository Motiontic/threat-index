/** Deterministic synthetic hot set for the search-index scale tests. Not part of the bundle. */
import type { VulnRow } from './search-index.ts';

/** `summaryWords` > 0 gives each row a summary of that many words from a skewed 30,000-word vocabulary. */
export function synthetic(entries: number, summaryWords = 0): VulnRow[] {
  // A deterministic LCG, so the skew is the same on every run.
  let seed = 12345;
  const rnd = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 2 ** 32;
  };
  const rows: VulnRow[] = [];
  const letters = 'abcdefghijklmnopqrstuvwxyz';
  for (let i = 0; i < entries; i++) {
    const words: string[] = [];
    if (rnd() < 0.6) words.push('apache'); // a few terms in more than half the titles
    if (rnd() < 0.55) words.push('vulnerability');
    if (rnd() < 0.52) words.push('log4j');
    if (rnd() < 0.5) words.push(`ap${Math.floor(rnd() * 40_000).toString(36)}`); // many terms sharing `ap`
    if (rnd() < 0.5) words.push(`la${Math.floor(rnd() * 40_000).toString(36)}`);
    if (rnd() < 0.4) words.push(`lo${Math.floor(rnd() * 40_000).toString(36)}`);
    words.push(`prod${Math.floor(rnd() * 5000)}`);
    words.push(`${letters[i % 26]}item`);
    rows.push({
      key: `CVE-2026-${String(i).padStart(6, '0')}`,
      kind: 'cve',
      title: `${words.join(' ')} flaw ${i}`,
      summary: Array.from(
        { length: summaryWords },
        () => `w${Math.floor(rnd() ** 3 * 30_000).toString(36)}`,
      ).join(' '),
      modified: new Date(Date.UTC(2026, 0, 1) + i * 60_000).toISOString(),
      hot: 1,
      published: '2026-01-01',
    });
  }
  return rows;
}
