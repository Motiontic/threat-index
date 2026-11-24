import { PRODUCT_INTRO } from '@ti/core/brand';
import { Link } from 'react-router';
import { SearchForm } from '../components/shell';
import { CompactRow, Panel, Tile } from '../components/ui';
import { getData } from '../data/data.server';
import type { SearchHit } from '../data/types';
import { formatDate, TYPE_PLURALS } from '../lib/format';
import { buildMeta, HOME_TITLE, pageTitle } from '../lib/seo';
import { siteOrigin } from '../lib/site.server';
import type { Route } from './+types/home';

export async function loader({ request }: Route.LoaderArgs) {
  let kev: SearchHit[] = [];
  try {
    kev = (await getData(request).search({ sig: ['kev'], sort: 'new' })).hits.slice(0, 5);
  } catch {
    // The panel is left out; the page is still 200.
  }
  return { origin: siteOrigin(request), kev };
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

const TILES = [
  { type: 'vuln', label: 'Vulnerabilities', to: '/search?type=vuln' },
  { type: 'kev', label: 'Exploited in the wild', to: '/search?sig=kev' },
  { type: 'breach', label: 'Breaches', to: '/search?type=breach' },
  { type: 'ai', label: 'AI incidents', to: '/search?type=ai' },
  { type: 'mal', label: 'Malicious packages', to: '/search?type=mal' },
];

export default function Home({ loaderData }: Route.ComponentProps) {
  const { kev } = loaderData;
  return (
    <div className="stack">
      <section className="hero">
        <h1>
          Every vulnerability, exploit, breach and AI incident, <em>in one place</em>.
        </h1>
        <p className="lede">
          {PRODUCT_INTRO}, keeps one record for each public security issue, with the exploited-in-the-wild
          flag and a credit for every source that reported it.
        </p>
        <SearchForm large />
        <div className="chips">
          {SUGGESTIONS.map((s) => (
            <Link key={s.q} className="pill" to={`/search?q=${encodeURIComponent(s.q)}`}>
              {s.label}
            </Link>
          ))}
        </div>
      </section>

      <section aria-labelledby="types-title">
        <h2 id="types-title" className="visually-hidden">
          Browse by type
        </h2>
        <div className="tiles">
          {TILES.map((t) => (
            <Tile key={t.type} kev={t.type === 'kev'} label={t.label} to={t.to} />
          ))}
        </div>
      </section>

      <div className="columns-2">
        {kev.length > 0 ? (
          <Panel title="Exploited in the wild, latest">
            <ul>
              {kev.map((h) => (
                <CompactRow key={h.key} item={h} note={formatDate(h.published)} />
              ))}
            </ul>
          </Panel>
        ) : null}
        <Panel title="Browse by type">
          <div className="chips">
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
    </div>
  );
}
