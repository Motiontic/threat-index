import { PRODUCT_INTRO, PRODUCT_NAME, PRODUCT_SHORT } from '@ti/core/brand';
import { NVD_NOTICE } from '@ti/core/licence';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { Form, Link, useLocation, useNavigation } from 'react-router';
import { AccountButton, useAuthState } from '../lib/auth';
import { disclosure } from '../lib/menu-nav';
import { type Theme, themeCookie } from '../lib/theme';
import { Chevron } from './controls';
import { Palette } from './palette';

const REPO = 'https://github.com/Motiontic/threat-index';

export const SAMPLE_BAND_TEXT = `Preview with sample data. Live records arrive when the site is connected to the ${PRODUCT_SHORT} API.`;

export function SkipLink() {
  return (
    <a className="skip-link" href="#content">
      Skip to content
    </a>
  );
}

export interface NavItem {
  label: string;
  to: string;
  /** Matches the current location when true. */
  current: (path: string, search: URLSearchParams) => boolean;
  count?: number;
}

const filter =
  (type: string): NavItem['current'] =>
  (p, s) =>
    p === '/search' && s.get('type') === type && !s.get('sig');

/** The pills in the top bar, in order. */
export const MAIN_LINKS: NavItem[] = [
  { label: 'Discover', to: '/', current: (p) => p === '/' },
  {
    label: 'Exploited',
    to: '/search?sig=kev',
    current: (p, s) => p === '/search' && s.get('sig') === 'kev',
  },
  { label: 'Vulnerabilities', to: '/search?type=vuln', current: filter('vuln') },
  { label: 'Breaches', to: '/breaches', current: (p) => p === '/breaches' || p.startsWith('/breach/') },
  {
    label: 'AI incidents',
    to: '/incidents?kind=ai',
    current: (p, s) => p === '/incidents' && s.get('kind') === 'ai',
  },
];

/** The items under "More". */
export function moreLinks(sourceCount: number | null): NavItem[] {
  return [
    { label: 'Index A–Z', to: '/index', current: (p) => p === '/index' || p.startsWith('/index/') },
    { label: 'Malicious packages', to: '/search?type=mal', current: filter('mal') },
    {
      label: 'Techniques',
      to: '/techniques?framework=attack&framework=atlas&framework=capec',
      current: (p, s) =>
        (p === '/techniques' && !s.getAll('framework').includes('cwe')) || p.startsWith('/technique/'),
    },
    {
      label: 'Terms',
      to: '/techniques?framework=cwe',
      current: (p, s) => p === '/techniques' && s.getAll('framework').includes('cwe'),
    },
    {
      label: 'Cyber operations',
      to: '/incidents?kind=cyber',
      current: (p, s) => p === '/incidents' && s.get('kind') === 'cyber',
    },
    {
      label: 'Sources',
      to: '/sources',
      current: (p) => p === '/sources',
      ...(sourceCount === null ? {} : { count: sourceCount }),
    },
  ];
}

function MoreMenu({
  items,
  path,
  search,
  onNavigate,
}: {
  items: NavItem[];
  path: string;
  search: URLSearchParams;
  onNavigate: () => void;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const here = `${path}?${search.toString()}`;
  const on = items.some((i) => i.current(path, search));

  const apply = useCallback((event: 'escape' | 'outside' | 'navigate') => {
    const next = disclosure({ open: true, returnFocus: false }, event);
    setOpen(next.open);
    if (next.returnFocus) button.current?.focus();
  }, []);

  // Navigation closes it.
  const last = useRef(here);
  useEffect(() => {
    if (last.current !== here) {
      last.current = here;
      apply('navigate');
    }
  }, [here, apply]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') apply('escape');
    };
    const onDown = (e: PointerEvent) => {
      if (!root.current?.contains(e.target as Node)) apply('outside');
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('pointerdown', onDown);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('pointerdown', onDown);
    };
  }, [open, apply]);

  return (
    <div className={on ? 'more on' : 'more'} ref={root}>
      <button
        ref={button}
        type="button"
        className="more-button"
        aria-expanded={open}
        aria-controls="more-list"
        onClick={() => setOpen((o) => !o)}
      >
        More
        <Chevron />
      </button>
      {/* Hidden until opened; the narrow layout shows the list expanded inside the menu panel. */}
      <ul id="more-list" className="more-list" hidden={!open}>
        {items.map((item) => (
          <li key={item.label}>
            <Link
              to={item.to}
              aria-current={item.current(path, search) ? 'page' : undefined}
              onClick={onNavigate}
            >
              {item.label}
              {item.count === undefined ? null : <span className="num">{item.count}</span>}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

function SearchIcon() {
  return (
    <svg className="ico" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <circle cx="7" cy="7" r="4.6" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <path d="m10.6 10.6 3 3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

function SparkleIcon() {
  return (
    <svg className="ico" width="20" height="20" viewBox="0 0 20 20" aria-hidden="true" focusable="false">
      <path
        d="M10 2.5 11.7 8.3 17.5 10l-5.8 1.7L10 17.5l-1.7-5.8L2.5 10l5.8-1.7z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** The search box. The top bar's has the ⌘K key button; the home page's is the large ask box. */
export function SearchForm({
  defaultValue = '',
  large = false,
  onOpenPalette,
}: {
  defaultValue?: string;
  large?: boolean;
  onOpenPalette?: () => void;
}) {
  const id = large ? 'q-home' : 'q-top';
  return (
    <Form
      method="get"
      action="/search"
      role="search"
      className={large ? 'search-form search-form-large bigs' : 'search-form'}
      id={large ? undefined : 'topForm'}
    >
      <label className="visually-hidden" htmlFor={id}>
        Search the index
      </label>
      {large ? <SparkleIcon /> : <SearchIcon />}
      <input
        id={id}
        className="input"
        type="search"
        name="q"
        defaultValue={defaultValue}
        placeholder="Search or ask anything"
        maxLength={200}
        autoComplete="off"
      />
      {large ? (
        <button type="submit" className="button button-accent">
          Search
        </button>
      ) : onOpenPalette ? (
        <button
          type="button"
          className="kb"
          aria-label="Open quick search"
          aria-keyshortcuts="Control+K Meta+K"
          onClick={onOpenPalette}
        >
          ⌘K
        </button>
      ) : null}
    </Form>
  );
}

function MoonIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        d="M13.2 9.6A5.6 5.6 0 0 1 6.4 2.8a5.6 5.6 0 1 0 6.8 6.8z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
    </svg>
  );
}
function SunIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <circle cx="8" cy="8" r="2.8" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <path
        d="M8 1.5v1.8M8 12.7v1.8M1.5 8h1.8M12.7 8h1.8M3.4 3.4l1.3 1.3M11.3 11.3l1.3 1.3M12.6 3.4l-1.3 1.3M4.7 11.3l-1.3 1.3"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Moon and sun buttons with a sliding thumb. The choice is a cookie, so the server renders the right theme. */
export function ThemeToggle({ initial }: { initial: Theme | null }) {
  const [theme, setTheme] = useState<Theme | null>(initial);
  // No stored choice: show what `prefers-color-scheme` gives.
  useEffect(() => {
    if (initial === null)
      setTheme(window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  }, [initial]);
  const choose = (next: Theme) => {
    setTheme(next);
    document.documentElement.dataset.theme = next;
    // biome-ignore lint/suspicious/noDocumentCookie: the Cookie Store API is not in every browser we support
    document.cookie = themeCookie(next, window.location.protocol === 'https:');
  };
  return (
    <fieldset className="theme">
      <legend className="visually-hidden">Colour theme</legend>
      <span className="thumb" aria-hidden="true" />
      <button type="button" aria-label="Dark" aria-pressed={theme === 'dark'} onClick={() => choose('dark')}>
        <MoonIcon />
      </button>
      <button
        type="button"
        aria-label="Light"
        aria-pressed={theme === 'light'}
        onClick={() => choose('light')}
      >
        <SunIcon />
      </button>
    </fieldset>
  );
}

/** A thin accent bar at the top while a navigation is pending, so a click answers at once. */
export function NavProgress() {
  const navigation = useNavigation();
  return (
    <div
      className="progress"
      data-active={navigation.state !== 'idle' ? 'true' : undefined}
      aria-hidden="true"
    />
  );
}

function AccountArea() {
  const { isSignedIn, available } = useAuthState();
  if (isSignedIn)
    return (
      <div className="authwrap">
        <Link to="/account" className="ibtn">
          Account
        </Link>
        <AccountButton />
      </div>
    );
  if (!available)
    return (
      <div className="authwrap">
        <span className="ibtn" aria-disabled="true">
          Sign-in is unavailable
        </span>
      </div>
    );
  return (
    <div className="authwrap">
      <Link to="/sign-in" className="ibtn ghost">
        Log in
      </Link>
      <Link to="/sign-up" className="ibtn pri">
        Sign up free
      </Link>
    </div>
  );
}

function FooterAccountLink() {
  const { isSignedIn, available } = useAuthState();
  if (isSignedIn) return <Link to="/account">Account</Link>;
  return available ? <Link to="/sign-in">Log in</Link> : null;
}

/** One quiet line: the credit, the licence and the links. */
export function Footer({ sourceCount }: { sourceCount: number | null }) {
  return (
    <footer className="sitefoot">
      <p>
        <Link to="/sources">
          {sourceCount === null ? 'Data from public sources' : `Data from ${sourceCount} public sources`},
          credited on every page.
        </Link>{' '}
        {NVD_NOTICE} {PRODUCT_INTRO}. Code under Apache-2.0;{' '}
        <a href={`${REPO}/blob/main/DATA_LICENSES.md`}>each source’s data keeps its own licence</a>.
      </p>
      <nav className="footer-links" aria-label="Explore">
        <Link to="/">Home</Link>
        <Link to="/index">Index A–Z</Link>
        <Link to="/search">Search everything</Link>
        <Link to="/sources">Sources</Link>
        <Link to="/privacy">Privacy</Link>
        <FooterAccountLink />
        <a href={REPO}>Code on GitHub</a>
      </nav>
    </footer>
  );
}

function MenuIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true" focusable="false">
      <path d="M2 4.5h14M2 9h14M2 13.5h14" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

export function Shell({
  sample,
  sourceCount,
  query,
  theme = null,
  persistent,
  children,
}: {
  sample: boolean;
  sourceCount: number | null;
  query?: string;
  theme?: Theme | null;
  /** Rendered in `main` outside the route-keyed wrapper, so it keeps its state across navigations. */
  persistent?: ReactNode;
  children: ReactNode;
}) {
  const location = useLocation();
  const search = new URLSearchParams(location.search);
  const [menuOpen, setMenuOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const closePalette = useCallback(() => setPaletteOpen(false), []);

  // Navigation closes the mobile menu.
  const here = `${location.pathname}${location.search}`;
  const lastHere = useRef(here);
  useEffect(() => {
    if (lastHere.current !== here) {
      lastHere.current = here;
      setMenuOpen(false);
    }
  }, [here]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      } else if (e.key === 'Escape' && menuOpen) {
        setMenuOpen(false);
        menuButton.current?.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [menuOpen]);

  const more = moreLinks(sourceCount);
  return (
    <>
      <SkipLink />
      <NavProgress />
      {sample ? <div className="banner band">{SAMPLE_BAND_TEXT}</div> : null}
      <div className="app">
        <header className="bar" data-open={menuOpen ? 'true' : 'false'}>
          <Link to="/" className="brand" aria-label={PRODUCT_NAME}>
            <span className="brand-dot" aria-hidden="true" />
            <b>{PRODUCT_SHORT}</b>
            <small>by Motiontic</small>
          </Link>
          <nav className="nav" id="site-nav" aria-label="Main">
            {MAIN_LINKS.map((item) => (
              <Link
                key={item.label}
                to={item.to}
                className="nav-pill"
                aria-current={item.current(location.pathname, search) ? 'page' : undefined}
              >
                {item.label}
              </Link>
            ))}
            <MoreMenu
              items={more}
              path={location.pathname}
              search={search}
              onNavigate={() => setMenuOpen(false)}
            />
          </nav>
          <SearchForm defaultValue={query} onOpenPalette={() => setPaletteOpen(true)} />
          <ThemeToggle initial={theme} />
          <AccountArea />
          <button
            ref={menuButton}
            type="button"
            className="menu-button"
            aria-expanded={menuOpen}
            aria-controls="site-nav"
            aria-label="Menu"
            onClick={() => setMenuOpen((o) => !o)}
          >
            <MenuIcon />
          </button>
        </header>
        <main id="content" className="main">
          {/* Only the page content fades up on navigation; the bar above stays put. */}
          {persistent}
          <div className="page rise" key={location.pathname}>
            {children}
          </div>
        </main>
        <Footer sourceCount={sourceCount} />
      </div>
      <Palette open={paletteOpen} onClose={closePalette} />
    </>
  );
}
