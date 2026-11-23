import { describe, expect, it } from 'vitest';
import { readWeb } from './read-app';

const tokensCss = readWeb('app/styles/tokens.css');

type Theme = Record<string, string>;

function block(css: string, start: RegExp): Theme {
  const m = start.exec(css);
  if (!m) throw new Error(`no block for ${start}`);
  const body = css.slice(m.index + m[0].length, css.indexOf('}', m.index));
  return Object.fromEntries(
    [...body.matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)].map((x) => [x[1] ?? '', (x[2] ?? '').trim()]),
  );
}

const light = block(tokensCss, /:root \{/);
const dark: Theme = { ...light, ...block(tokensCss, /:root\[data-theme=['"]dark['"]\] \{/) };
const dark2: Theme = { ...light, ...block(tokensCss, /:root:not\(\[data-theme=['"]light['"]\]\) \{/) };

const rgb = (hex: string): [number, number, number] => {
  const n = Number.parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
};
const lin = (c: number) => {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
};
const lum = ([r, g, b]: [number, number, number]) => 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
export const ratio = (a: string, b: string) => {
  const [hi, lo] = [lum(rgb(a)), lum(rgb(b))].sort((x, y) => y - x);
  return ((hi ?? 0) + 0.05) / ((lo ?? 0) + 0.05);
};
interface Pair {
  use: string;
  fg: (t: Theme) => string;
  bg: (t: Theme) => string;
  min: number;
}
const t = (name: string) => (th: Theme) => th[name] ?? '';
export const PAIRS: Pair[] = [
  { use: 'body text: ink on canvas', fg: t('ink'), bg: t('canvas'), min: 4.5 },
  { use: 'body text: ink on paper', fg: t('ink'), bg: t('paper'), min: 4.5 },
  { use: 'secondary text: ink-2 on canvas', fg: t('ink-2'), bg: t('canvas'), min: 4.5 },
  { use: 'secondary text: ink-2 on paper', fg: t('ink-2'), bg: t('paper'), min: 4.5 },
  { use: 'chip text: ink-2 on neutral fill', fg: t('ink-2'), bg: t('fill'), min: 4.5 },
  { use: 'muted text: ink-3 on canvas', fg: t('ink-3'), bg: t('canvas'), min: 4.5 },
  { use: 'muted text: ink-3 on paper', fg: t('ink-3'), bg: t('paper'), min: 4.5 },
  { use: 'muted text: ink-3 on neutral fill', fg: t('ink-3'), bg: t('fill'), min: 4.5 },
  { use: 'accent text: accent-ink on canvas', fg: t('accent-ink'), bg: t('canvas'), min: 4.5 },
  { use: 'accent text: accent-ink on paper', fg: t('accent-ink'), bg: t('paper'), min: 4.5 },
  { use: 'KEV chip and tile: ink on accent-soft', fg: t('ink'), bg: t('accent-soft'), min: 4.5 },
  { use: 'tile: tile-ink on tile', fg: t('tile-ink'), bg: t('tile'), min: 4.5 },
  { use: 'active nav link and band: on-ink on ink', fg: t('on-ink'), bg: t('ink'), min: 4.5 },
  { use: 'status text: ok on paper', fg: t('ok'), bg: t('paper'), min: 4.5 },
  { use: 'status text: ok on canvas', fg: t('ok'), bg: t('canvas'), min: 4.5 },
  { use: 'status chip and badge text: warn on paper', fg: t('warn'), bg: t('paper'), min: 4.5 },
  { use: 'status text: bad on paper', fg: t('bad'), bg: t('paper'), min: 4.5 },
  { use: 'type badge (ai): tile-ink on tile', fg: t('tile-ink'), bg: t('tile'), min: 4.5 },
  { use: 'type badge (mal): accent-ink on paper', fg: t('accent-ink'), bg: t('paper'), min: 4.5 },
  { use: 'type badge (term): ink-2 on neutral fill', fg: t('ink-2'), bg: t('fill'), min: 4.5 },
  { use: 'focus ring: accent-ink on canvas (3:1)', fg: t('accent-ink'), bg: t('canvas'), min: 3 },
  { use: 'focus ring: accent-ink on paper (3:1)', fg: t('accent-ink'), bg: t('paper'), min: 3 },
  { use: 'CVSS meter, bad fill on its track (3:1)', fg: t('bad'), bg: t('fill'), min: 3 },
  { use: 'CVSS meter, ink-2 fill on its track (3:1)', fg: t('ink-2'), bg: t('fill'), min: 3 },
];

const themes: [string, Theme][] = [
  ['light', light],
  ['dark (data-theme)', dark],
  ['dark (prefers-color-scheme)', dark2],
];

describe('tokens', () => {
  it('has the exact light and dark palettes from the spec', () => {
    expect(light).toMatchObject({
      canvas: '#fafaf8',
      paper: '#ffffff',
      ink: '#121212',
      'ink-2': '#4a4a47',
      'ink-3': '#6b6a64',
      line: '#e6e4de',
      'line-2': '#d6d3cb',
      fill: '#edebe6',
      tile: '#eeeffc',
      'tile-ink': '#2b2f6b',
      accent: '#ef7d45',
      'accent-soft': '#fdebe1',
      'accent-ink': '#b4501c',
      ok: '#2f7a55',
      warn: '#9a5f0a',
      bad: '#c23b1f',
      shadow: '0 1px 2px rgb(18 18 18 / 5%)',
    });
    expect(dark).toMatchObject({
      canvas: '#111110',
      paper: '#1a1a18',
      ink: '#f2f1ec',
      'ink-2': '#bdbbb3',
      'ink-3': '#9a988f',
      line: '#2c2b28',
      'line-2': '#3a3935',
      fill: '#242320',
      tile: '#22243f',
      'tile-ink': '#c9ccf7',
      accent: '#f2905e',
      'accent-soft': '#3a2418',
      'accent-ink': '#f2905e',
      ok: '#5db487',
      warn: '#e0a040',
      bad: '#f0664a',
      shadow: 'none',
    });
  });

  it('applies dark under prefers-color-scheme the same as under data-theme="dark"', () => {
    for (const [k, v] of Object.entries(dark)) {
      if (k === 'canvas-90' || k === 'backdrop' || k === 'on-ink') continue;
      expect(dark2[k], k).toBe(v);
    }
  });

  it('defines every radius and type size from the spec', () => {
    expect(light).toMatchObject({
      'radius-sm': '8px',
      'radius-md': '10px',
      'radius-lg': '12px',
      'radius-xl': '14px',
      'radius-pill': '99px',
      'text-body': '14px',
      'text-muted': '12px',
      'text-label': '11px',
      'text-card-title': '16px',
      'text-heading': '24px',
      'text-entry': 'clamp(24px, 3vw, 32px)',
      'text-hero': 'clamp(28px, 4.2vw, 44px)',
      'text-tile': '24px',
    });
  });
});

describe('contrast', () => {
  it.each(themes.flatMap(([name, th]) => PAIRS.map((p) => [name, p.use, th, p] as const)))(
    '%s: %s',
    (_name, _use, th, p) => {
      expect(ratio(p.fg(th), p.bg(th))).toBeGreaterThanOrEqual(p.min);
    },
  );

  it('keeps the brand accent off text: it is below 4.5:1 on canvas, which is why accent-ink exists', () => {
    expect(ratio(light.accent ?? '', light.canvas ?? '')).toBeLessThan(3);
    expect(ratio(light['accent-ink'] ?? '', light.canvas ?? '')).toBeGreaterThanOrEqual(4.5);
  });

  it('prints the ratio table when asked', () => {
    if (!import.meta.env.VITE_CONTRAST_TABLE) return;
    const rows = PAIRS.map(
      (p) =>
        `| ${p.use} | ${ratio(p.fg(light), p.bg(light)).toFixed(2)} | ${ratio(p.fg(dark), p.bg(dark)).toFixed(2)} | ${p.min} |`,
    );
    console.log(`\n| Pair | Light | Dark | Needs |\n| --- | --- | --- | --- |\n${rows.join('\n')}`);
  });
});
