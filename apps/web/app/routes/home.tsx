import { PRODUCT_INTRO } from '@ti/core/brand';
import { SOURCES } from '@ti/sources/registry';
import { Link } from 'react-router';
import { SearchForm } from '../components/shell';
import { Panel, Tile } from '../components/ui';
import { getData } from '../data/data.server';
import type { HomeChange, HomeCounts, HomeItem, HomeResponse } from '../data/types';
import { formatDate, TYPE_PLURALS } from '../lib/format';
import { buildMeta, HOME_TITLE, pageTitle } from '../lib/seo';
import { siteOrigin } from '../lib/site.server';
import type { Route } from './+types/home';

export async function loader({ request }: Route.LoaderArgs) {
  let home: HomeResponse | null = null;
  try {
    home = await getData(request).home();
  } catch {
    // The count tiles and panels are left out; the page is still 200.
  }
  return { origin: siteOrigin(request), home, sourceCount: SOURCES.length };
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  return buildMeta({
    title: HOME_TITLE,
    description:
      'Search one record of public vulnerabilities, exploited-in-the-wild flags, breaches and AI incidents, with every source credited.',
    path: '/',
    origin: loaderData.origin,
  });
}

const SUGGESTIONS = [
  { label: 'CVE-2025-3248', q: 'CVE-2025-3248' },
  { label: 'log4j', q: 'log4j' },
  { label: 'ransomware', q: 'ransomware' },
  { label: 'supply chain', q: 'supply chain' },
];

const TILES: { count: keyof HomeCounts; label: string; to?: string; kev?: boolean }[] = [
  { count: 'vulnerabilities', label: 'Vulnerabilities', to: '/search?type=vuln' },
  { count: 'exploited', label: 'Exploited in the wild', to: '/search?sig=kev', kev: true },
  { count: 'exploits', label: 'Public exploits' },
  { count: 'breaches', label: 'Breaches', to: '/breaches' },
  { count: 'aiIncidents', label: 'AI incidents', to: '/incidents?kind=ai' },
  { count: 'cyberOperations', label: 'Cyber operations', to: '/incidents?kind=cyber_op' },
  { count: 'maliciousPackages', label: 'Malicious packages', to: '/search?type=mal' },
  { count: 'techniques', label: 'Techniques', to: '/techniques' },
];

const CHANGE_LABELS: Record<string, string> = {
  newly_exploited: 'Newly exploited',
  public_exploit: 'Public exploit',
  epss_band: 'Exploit likelihood changed',
  fix_released: 'Fix released',
  cvss_change: 'Score changed',
  breach_notice: 'New breach notice',
  new_advisory: 'New advisory',
};

function itemTo(i: HomeItem): string {
  if (i.type === 'breach') return `/breach/${encodeURIComponent(i.key)}`;
  if (i.type === 'ai') return `/incident/${encodeURIComponent(i.source ?? '')}/${encodeURIComponent(i.key)}`;
  return `/e/${encodeURIComponent(i.key)}`;
}

function ItemRows({ items }: { items: HomeItem[] }) {
  return (
    <ul>
      {items.map((i) => (
        <li key={`${i.source ?? ''}/${i.key}`} className="row">
          <span className="mono muted">
            {i.type === 'vuln' || i.type === 'mal' ? i.key : formatDate(i.date)}
          </span>
          <span className="row-main">
            <Link to={itemTo(i)}>{i.title}</Link>
          </span>
          {i.signal || i.date ? <span className="muted">{i.signal ?? formatDate(i.date)}</span> : null}
        </li>
      ))}
    </ul>
  );
}

function ChangeRows({ changes }: { changes: HomeChange[] }) {
  return (
    <ul>
      {changes.map((c) => (
        <li key={`${c.key}/${c.kind}/${c.at}`} className="row">
          <span className="mono muted">{formatDate(c.at)}</span>
          <span className="row-main">
            <Link
              to={
                c.type === 'breach'
                  ? `/breach/${encodeURIComponent(c.key)}`
                  : `/e/${encodeURIComponent(c.key)}`
              }
            >
              {c.title ?? c.key}
            </Link>
          </span>
          <span className="muted">{CHANGE_LABELS[c.kind] ?? 'Changed'}</span>
        </li>
      ))}
    </ul>
  );
}

export default function Home({ loaderData }: Route.ComponentProps) {
  const { home, sourceCount } = loaderData;
  const panels = home
    ? [
        {
          id: 'exploited',
          span: 's7',
          title: 'Exploited in the wild, latest',
          items: home.lists.exploited,
          all: '/search?sig=kev',
        },
        {
          id: 'vulnerabilities',
          span: 's4',
          title: 'Latest vulnerabilities',
          items: home.lists.vulnerabilities,
          all: '/search?type=vuln&sort=new',
        },
        {
          id: 'exploits',
          span: 's4',
          title: 'Latest public exploits',
          items: home.lists.exploits,
          all: undefined,
        },
        {
          id: 'breaches',
          span: 's4',
          title: 'Recent breaches',
          items: home.lists.breaches,
          all: '/breaches',
        },
        {
          id: 'ai',
          span: 's6',
          title: 'Recent AI incidents',
          items: home.lists.aiIncidents,
          all: '/incidents?kind=ai',
        },
        {
          id: 'mal',
          span: 's6',
          title: 'Latest malicious packages',
          items: home.lists.maliciousPackages,
          all: '/search?type=mal&sort=new',
        },
      ].filter((p) => p.items.length > 0)
    : [];
  const changes = home && home.changes.length > 0 ? home.changes : null;
  return (
    <div className="stack">
      <section className="hero">
        <p className="live">
          <i aria-hidden="true" />
          {sourceCount
            ? `Updated every 3 hours from ${sourceCount} public sources`
            : 'Updated every 3 hours from public sources'}
        </p>
        <h1>
          Every vulnerability, exploit and breach, <em>as it happens.</em>
        </h1>
        <p className="lede">
          {PRODUCT_INTRO}, keeps one record for each public security issue, with the exploited-in-the-wild
          flag and a credit for every source that reported it.
        </p>
        <SearchForm large />
        <div className="chips sugg">
          {SUGGESTIONS.map((s) => (
            <Link key={s.q} className="pill" to={`/search?q=${encodeURIComponent(s.q)}`}>
              {s.label}
            </Link>
          ))}
        </div>
      </section>

      {home ? (
        <section aria-labelledby="types-title">
          <h2 id="types-title" className="visually-hidden">
            Records by type
          </h2>
          <div className="tiles">
            {TILES.map((t) => {
              const n = home.counts[t.count];
              const tile = { label: t.label, count: n, ...(t.to ? { to: t.to } : {}), kev: t.kev ?? false };
              return <Tile key={t.count} {...tile} {...(n === 0 ? { note: 'Coming soon' } : {})} />;
            })}
          </div>
        </section>
      ) : null}

      {panels.length > 0 || changes ? (
        <section aria-labelledby="latest-title">
          <div className="sec2">
            <h2 id="latest-title">Latest</h2>
          </div>
          <div className="bento">
            {panels
              .filter((p) => p.id === 'exploited')
              .map((p) => (
                <HomePanel key={p.id} panel={p} />
              ))}
            {changes ? (
              <div className="s5">
                <Panel title="What changed">
                  <ChangeRows changes={changes} />
                </Panel>
              </div>
            ) : null}
            {panels
              .filter((p) => p.id !== 'exploited')
              .map((p) => (
                <HomePanel key={p.id} panel={p} />
              ))}
          </div>
        </section>
      ) : null}

      <Panel title="Browse by type">
        <div className="chips browse">
          {(Object.keys(TYPE_PLURALS) as (keyof typeof TYPE_PLURALS)[]).map((t) => (
            <Link key={t} className="pill" to={`/search?type=${t}`}>
              {TYPE_PLURALS[t]}
            </Link>
          ))}
          <Link className="pill" to="/search?sig=kev">
            Exploited in the wild
          </Link>
        </div>
      </Panel>
    </div>
  );
}

function HomePanel({
  panel,
}: {
  panel: { span: string; title: string; items: HomeItem[]; all: string | undefined };
}) {
  return (
    <div className={panel.span}>
      <Panel title={panel.title} {...(panel.all ? { seeAll: { to: panel.all } } : {})}>
        <ItemRows items={panel.items} />
      </Panel>
    </div>
  );
}
