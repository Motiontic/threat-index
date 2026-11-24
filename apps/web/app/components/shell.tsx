import { PRODUCT_INTRO, PRODUCT_NAME, PRODUCT_SHORT } from '@ti/core/brand';
import { NVD_NOTICE } from '@ti/core/licence';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { Form, Link, useLocation } from 'react-router';
import { AccountButton, useAuthState } from '../lib/auth';
import { SignInButtons } from './account-bits';

const REPO = 'https://github.com/Motiontic/threat-index';

export const SAMPLE_BAND_TEXT = `Preview with sample data. Live records arrive when the site is connected to the ${PRODUCT_SHORT} API.`;

export function SkipLink() {
  return (
    <a className="skip-link" href="#content">
      Skip to content
    </a>
  );
}

interface NavItem {
  label: string;
  to: string;
  /** Matches the current location when true. */
  current: (path: string, search: URLSearchParams) => boolean;
  count?: number;
}

function navSections(
  sourceCount: number | null,
  auth: { isSignedIn: boolean; available: boolean },
): { title: string; items: NavItem[] }[] {
  const filter =
    (type: string): NavItem['current'] =>
    (p, s) =>
      p === '/search' && s.get('type') === type;
  return [
    {
      title: 'Explore',
      items: [
        { label: 'Home', to: '/', current: (p) => p === '/' },
        { label: 'Index A–Z', to: '/index', current: (p) => p === '/index' || p.startsWith('/index/') },
        {
          label: 'Search everything',
          to: '/search',
          current: (p, s) => p === '/search' && !s.get('type') && !s.get('sig'),
        },
      ],
    },
    {
      title: 'Browse',
      items: [
        { label: 'Vulnerabilities', to: '/search?type=vuln', current: filter('vuln') },
        {
          label: 'Exploited in the wild',
          to: '/search?sig=kev',
          current: (p, s) => p === '/search' && s.get('sig') === 'kev',
        },
        {
          label: 'Breaches',
          to: '/breaches',
          current: (p) => p === '/breaches' || p.startsWith('/breach/'),
        },
        {
          label: 'AI incidents',
          to: '/incidents?kind=ai',
          current: (p, s) => p === '/incidents' && s.get('kind') === 'ai',
        },
        {
          label: 'Cyber operations',
          to: '/incidents?kind=cyber',
          current: (p, s) => p === '/incidents' && s.get('kind') === 'cyber',
        },
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
      ],
    },
    {
      title: 'Data',
      items: [
        {
          label: 'Sources',
          to: '/sources',
          current: (p) => p === '/sources',
          ...(sourceCount === null ? {} : { count: sourceCount }),
        },
      ],
    },
    {
      title: 'You',
      items: auth.isSignedIn
        ? [{ label: 'Account', to: '/account', current: (p) => p === '/account' }]
        : auth.available
          ? [
              { label: 'Sign up free', to: '/sign-up', current: (p) => p.startsWith('/sign-up') },
              { label: 'Log in', to: '/sign-in', current: (p) => p.startsWith('/sign-in') },
            ]
          : [],
    },
  ];
}

function Rail({ sourceCount, onNavigate }: { sourceCount: number | null; onNavigate: () => void }) {
  const location = useLocation();
  const search = new URLSearchParams(location.search);
  const { isSignedIn, available } = useAuthState();
  return (
    <div className="rail" id="site-rail">
      <Link to="/" className="brand" aria-label={PRODUCT_NAME} onClick={onNavigate}>
        <span className="brand-dot" aria-hidden="true" />
        <span>
          <span className="brand-name">{PRODUCT_SHORT}</span>
          <br />
          <span className="brand-by">by Motiontic</span>
        </span>
      </Link>
      <nav aria-label="Main">
        {navSections(sourceCount, { isSignedIn, available })
          .filter((section) => section.items.length > 0)
          .map((section) => (
            <div className="nav-section" key={section.title}>
              <span className="label">{section.title}</span>
              <ul>
                {section.items.map((item) => (
                  <li key={item.label}>
                    <Link
                      to={item.to}
                      className="nav-link"
                      aria-current={item.current(location.pathname, search) ? 'page' : undefined}
                      onClick={onNavigate}
                    >
                      {item.label}
                      {item.count === undefined ? null : <span className="nav-count">{item.count}</span>}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
      </nav>
    </div>
  );
}

export function SearchForm({ defaultValue = '', large = false }: { defaultValue?: string; large?: boolean }) {
  return (
    <Form
      method="get"
      action="/search"
      role="search"
      className={large ? 'search-form search-form-large' : 'search-form'}
    >
      <label className="visually-hidden" htmlFor={large ? 'q-home' : 'q-top'}>
        Search the index
      </label>
      <input
        id={large ? 'q-home' : 'q-top'}
        className="input"
        type="search"
        name="q"
        defaultValue={defaultValue}
        placeholder="Search a CVE, product, breach or term"
        maxLength={200}
        autoComplete="off"
      />
      <button type="submit" className="button button-primary">
        Search
      </button>
    </Form>
  );
}

function FooterAccountLink() {
  const { isSignedIn, available } = useAuthState();
  if (isSignedIn) return <Link to="/account">Account</Link>;
  return available ? <Link to="/sign-in">Log in</Link> : null;
}

export function Footer({ sourceCount }: { sourceCount: number | null }) {
  return (
    <footer className="footer">
      <p>
        <Link to="/sources">
          {sourceCount === null ? 'Data from public sources' : `Data from ${sourceCount} public sources`},
          credited on every page.
        </Link>
      </p>
      <p>{NVD_NOTICE}</p>
      <p>
        {PRODUCT_INTRO}. Code under Apache-2.0;{' '}
        <a href={`${REPO}/blob/main/DATA_LICENSES.md`}>each source’s data keeps its own licence</a>.{' '}
        <a href={REPO}>Code on GitHub</a>.
      </p>
      <nav className="footer-links footer-explore" aria-label="Explore">
        <Link to="/">Home</Link>
        <Link to="/index">Index A–Z</Link>
        <Link to="/search">Search everything</Link>
        <Link to="/sources">Sources</Link>
        <FooterAccountLink />
      </nav>
    </footer>
  );
}

export function Shell({
  sample,
  sourceCount,
  query,
  children,
}: {
  sample: boolean;
  sourceCount: number | null;
  query?: string;
  children: ReactNode;
}) {
  const { isSignedIn } = useAuthState();
  const [open, setOpen] = useState(false);
  const button = useRef<HTMLButtonElement>(null);
  const rail = useRef<HTMLDivElement>(null);

  const close = useCallback((returnFocus: boolean) => {
    setOpen(false);
    if (returnFocus) button.current?.focus();
  }, []);

  useEffect(() => {
    if (!open) return;
    rail.current?.querySelector<HTMLElement>('a')?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close(true);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, close]);

  return (
    <>
      <SkipLink />
      {sample ? <div className="band">{SAMPLE_BAND_TEXT}</div> : null}
      <div className="shell" data-drawer={open ? 'open' : 'closed'}>
        <div ref={rail} className="rail-slot">
          <Rail sourceCount={sourceCount} onNavigate={() => close(true)} />
        </div>
        <button
          type="button"
          className="drawer-backdrop"
          aria-label="Close menu"
          tabIndex={-1}
          onClick={() => close(true)}
        />
        <div className="content-col">
          <header className="topbar">
            <button
              ref={button}
              type="button"
              className="menu-button"
              aria-expanded={open}
              aria-controls="site-rail"
              aria-label="Menu"
              onClick={() => setOpen((o) => !o)}
            >
              <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true" focusable="false">
                <path
                  d="M2 4.5h14M2 9h14M2 13.5h14"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                />
              </svg>
            </button>
            <div className="topbar-search">
              <SearchForm defaultValue={query} />
            </div>
            <div className="topbar-actions">
              {isSignedIn ? (
                <>
                  <Link to="/account" className="button">
                    Account
                  </Link>
                  <AccountButton />
                </>
              ) : (
                <SignInButtons />
              )}
            </div>
          </header>
          <main id="content" className="main">
            {children}
          </main>
          <Footer sourceCount={sourceCount} />
        </div>
      </div>
    </>
  );
}
