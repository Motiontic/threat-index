import { Link } from 'react-router';
import { SearchForm } from '../components/shell';
import { CompactRow, Panel, Tile } from '../components/ui';
import { getData } from '../data/data.server';
import { formatDate, TYPE_PLURALS } from '../lib/format';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/home';

export async function loader({ request }: Route.LoaderArgs) {
  return { origin: new URL(request.url).origin, ...getData(request).home() };
}

export function meta({ loaderData }: Route.MetaArgs) {
  return buildMeta({
    title: pageTitle('Every vulnerability, exploit, breach and AI incident'),
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

export default function Home({ loaderData }: Route.ComponentProps) {
  const { tiles, kev, breaches, changes } = loaderData;
  return (
    <div className="stack">
      <section className="hero">
        <h1>
          Every vulnerability, exploit, breach and AI incident, <em>in one place</em>.
        </h1>
        <p className="lede">
          One record for each public security issue, with the exploited-in-the-wild flag and a credit for
          every source that reported it.
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

      <section aria-labelledby="counts-title">
        <h2 id="counts-title" className="visually-hidden">
          Records by type
        </h2>
        <div className="tiles">
          {tiles.map((t) => (
            <Tile
              key={t.type}
              kev={t.type === 'kev'}
              count={t.count}
              label={t.label}
              to={t.type === 'kev' ? '/search?sig=kev' : `/search?type=${t.type}`}
            />
          ))}
        </div>
      </section>

      <div className="columns-2">
        <div className="stack">
          <Panel title="Exploited in the wild, latest">
            <ul>
              {kev.map((e) => (
                <CompactRow key={e.key} entry={e} note={`KEV ${formatDate(e.kev_added)}`} />
              ))}
            </ul>
          </Panel>
          <Panel title="Recent breaches">
            <p className="muted">Examples only: these records are invented samples.</p>
            <ul>
              {breaches.map((e) => (
                <CompactRow key={e.key} entry={e} note={formatDate(e.published)} />
              ))}
            </ul>
          </Panel>
        </div>
        <div className="stack">
          <Panel title="What changed">
            <ul>
              {changes.map((c) => (
                <li key={`${c.key}-${c.date}`} className="row">
                  <span className="mono muted">{formatDate(c.date)}</span>
                  <span className="row-main">
                    <Link to={`/e/${encodeURIComponent(c.key)}`}>{c.key}</Link>{' '}
                    <span className="muted">{c.text}</span>
                  </span>
                </li>
              ))}
            </ul>
          </Panel>
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
    </div>
  );
}
