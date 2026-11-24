import { renderToString } from 'react-dom/server';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { describe, expect, it, vi } from 'vitest';

vi.mock('cloudflare:workers', () => ({ env: {} }));

import { Segmented, Select, Switch } from '../app/components/controls';
import { MAIN_LINKS, moreLinks, Shell, ThemeToggle } from '../app/components/shell';
import { disclosure, moveIndex, trapTarget } from '../app/lib/menu-nav';
import { parseTheme, THEME_COOKIE, themeCookie } from '../app/lib/theme';

const at = (location: string, node: React.ReactElement) =>
  renderToString(
    <RouterProvider
      router={createMemoryRouter([{ path: '*', element: node }], { initialEntries: [location] })}
    />,
  );
const shell = (location: string, theme: 'light' | 'dark' | null = null) =>
  at(
    location,
    <Shell sample={false} sourceCount={55} theme={theme}>
      <h1>Page</h1>
    </Shell>,
  );

describe('theme cookie', () => {
  it('is read on the server from the Cookie header', () => {
    expect(parseTheme(`a=1; ${THEME_COOKIE}=dark; b=2`)).toBe('dark');
    expect(parseTheme(`${THEME_COOKIE}=light`)).toBe('light');
  });

  it('is null when missing or not a known value, so the page follows prefers-color-scheme', () => {
    expect(parseTheme(null)).toBeNull();
    expect(parseTheme('a=1')).toBeNull();
    expect(parseTheme(`${THEME_COOKIE}=<script>`)).toBeNull();
    expect(parseTheme(`x${THEME_COOKIE}=dark`)).toBeNull();
  });

  it('is written by the toggle as a one-year, site-wide, SameSite=Lax cookie', () => {
    const c = themeCookie('dark', true);
    expect(c).toBe(`${THEME_COOKIE}=dark; Path=/; Max-Age=31536000; SameSite=Lax; Secure`);
    expect(themeCookie('light', false)).not.toContain('Secure');
    expect(parseTheme(c)).toBe('dark');
  });

  it('renders the stored choice as pressed in the toggle, with a thumb and two buttons', () => {
    const dark = at('/', <ThemeToggle initial="dark" />);
    expect(dark).toMatch(/aria-label="Dark" aria-pressed="true"/);
    expect(dark).toMatch(/aria-label="Light" aria-pressed="false"/);
    expect(dark).toContain('class="thumb"');
    expect(at('/', <ThemeToggle initial="light" />)).toMatch(/aria-label="Light" aria-pressed="true"/);
  });
});

describe('top bar', () => {
  it('has no sidebar and carries the brand, links, More menu, search, theme and account', () => {
    const html = shell('/');
    expect(html).not.toContain('class="rail');
    expect(html).toContain('class="bar"');
    expect(html).toContain('by Motiontic');
    for (const l of MAIN_LINKS) expect(html).toContain(`>${l.label}</a>`);
    expect(html).toContain('Search or ask anything');
    expect(html).toContain('action="/search"');
    expect(html).toContain('aria-label="Colour theme"'.replace('aria-label="Colour theme"', 'Colour theme'));
  });

  it('puts the More items in a real button and a list that is hidden until opened', () => {
    const html = shell('/');
    expect(html).toMatch(/<button[^>]*class="more-button"[^>]*aria-expanded="false"/);
    expect(html).toMatch(/<ul id="more-list" class="more-list" hidden=""/);
    for (const l of moreLinks(55)) expect(html).toContain(l.label);
    expect(html.indexOf('Index A–Z')).toBeLessThan(html.indexOf('Sources</a>'));
  });

  it('marks the pill for the current route, and only that one', () => {
    const current = (loc: string) =>
      [...shell(loc).matchAll(/<a[^>]*aria-current="page"[^>]*>([^<]*)</g)].map((m) => m[1]);
    expect(current('/')).toEqual(['Discover']);
    expect(current('/search?sig=kev')).toEqual(['Exploited']);
    expect(current('/search?type=vuln')).toEqual(['Vulnerabilities']);
    expect(current('/breach/x')).toEqual(['Breaches']);
    expect(current('/incidents?kind=ai')).toEqual(['AI incidents']);
    // A page under More lights More and its own item.
    expect(shell('/sources')).toMatch(/class="more on"/);
    expect(current('/sources')).toEqual(['Sources']);
  });

  it('has no inline style and no script of its own', () => {
    const html = shell('/');
    expect(html).not.toMatch(/\sstyle=/);
    expect(html).not.toContain('<script');
  });
});

describe('disclosure rules (More menu, palette, dropdown)', () => {
  const closed = { open: false, returnFocus: false };
  const open = { open: true, returnFocus: false };

  it('opens and closes on the button, and the closing press returns focus', () => {
    expect(disclosure(closed, 'toggle').open).toBe(true);
    expect(disclosure(open, 'toggle')).toEqual({ open: false, returnFocus: true });
  });

  it('closes on Escape and returns focus to the button', () => {
    expect(disclosure(open, 'escape')).toEqual({ open: false, returnFocus: true });
  });

  it('closes on an outside press or navigation without stealing focus', () => {
    expect(disclosure(open, 'outside')).toEqual({ open: false, returnFocus: false });
    expect(disclosure(open, 'navigate')).toEqual({ open: false, returnFocus: false });
  });

  it('ignores close events while closed', () => {
    for (const e of ['escape', 'outside', 'navigate'] as const) expect(disclosure(closed, e)).toBe(closed);
  });

  it('traps Tab inside a dialog', () => {
    const items = ['input', 'a', 'b'];
    expect(trapTarget(items, 'b', false)).toBe('input');
    expect(trapTarget(items, 'input', true)).toBe('b');
    expect(trapTarget(items, 'a', false)).toBeNull();
    expect(trapTarget(items, null, false)).toBe('input');
    expect(trapTarget([], null, false)).toBeNull();
  });
});

describe('list keys', () => {
  it('moves with the arrows, wraps, and jumps with Home and End', () => {
    expect(moveIndex('ArrowDown', -1, 3)).toBe(0);
    expect(moveIndex('ArrowDown', 2, 3)).toBe(0);
    expect(moveIndex('ArrowUp', 0, 3)).toBe(2);
    expect(moveIndex('ArrowUp', -1, 3)).toBe(2);
    expect(moveIndex('Home', 2, 3)).toBe(0);
    expect(moveIndex('End', 0, 3)).toBe(2);
    expect(moveIndex('ArrowDown', 0, 0)).toBe(-1);
  });
});

describe('themed dropdown', () => {
  const options = [
    { value: '', label: 'Any' },
    { value: 'high', label: 'High' },
    { value: 'low', label: 'Low' },
  ];

  it('renders a native select with the same name and selected value for visitors without JavaScript', () => {
    const html = at(
      '/',
      <Select id="f-sev" name="sev" label="Severity" options={options} defaultValue="high" />,
    );
    expect(html).toMatch(/<select[^>]*id="f-sev"[^>]*name="sev"/);
    expect(html).toMatch(/<option value="high" selected="">High<\/option>/);
    // The themed button and listbox only appear after hydration.
    expect(html).not.toContain('role="listbox"');
    expect(html).not.toContain('class="xsel-b"');
  });

  it('keeps an empty value selected', () => {
    const html = at('/', <Select id="s" name="year" label="Year" options={options} defaultValue="" />);
    expect(html).toMatch(/<option value="" selected="">Any<\/option>/);
  });
});

describe('segmented control and switch', () => {
  it('sends the chosen sort as a radio value and positions the thumb on it', () => {
    const html = at(
      '/',
      <Segmented
        name="sort"
        label="Sort"
        defaultValue="new"
        options={[
          { value: 'rel', label: 'Best match' },
          { value: 'new', label: 'Newest' },
        ]}
      />,
    );
    expect(html).toContain('data-index="1"');
    const radios = [...html.matchAll(/<input[^>]*type="radio"[^>]*>/g)].map((m) => m[0]);
    expect(radios).toHaveLength(2);
    expect(radios.find((r) => r.includes('value="new"'))).toContain('checked');
    expect(radios.find((r) => r.includes('value="rel"'))).not.toContain('checked');
    expect(radios.every((r) => r.includes('name="sort"'))).toBe(true);
  });

  it('renders a switch as a labelled checkbox', () => {
    const html = at('/', <Switch name="instant" defaultChecked label="Instant alerts" />);
    expect(html).toMatch(
      /<input[^>]*type="checkbox"[^>]*class="switch"|<input[^>]*class="switch"[^>]*type="checkbox"/,
    );
    expect(html).toContain('Instant alerts');
  });
});
