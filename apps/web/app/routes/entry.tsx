import { data, Link, redirect } from 'react-router';
import { Chip, CreditList, CvssMeter, GateCard, TypeBadge } from '../components/ui';
import { getData } from '../data/data.server';
import type { EntryType } from '../data/types';
import { formatDate, TYPE_PLURALS } from '../lib/format';
import { useNonce } from '../lib/nonce';
import { buildMeta, JsonLd, pageTitle } from '../lib/seo';
import type { Route } from './+types/entry';

export async function loader({ request, params }: Route.LoaderArgs) {
  const id = params.id ?? '';
  const found = id.length > 100 ? null : getData(request).entry(id);
  if (!found) throw data(null, { status: 404 });
  // Another case or an alias goes to the one canonical address.
  if (found.entry.key !== id) throw redirect(`/e/${encodeURIComponent(found.entry.key)}`, 301);
  return { origin: new URL(request.url).origin, ...found };
}

export function meta({ loaderData }: Route.MetaArgs) {
  const { entry, origin } = loaderData;
  return buildMeta({
    title: pageTitle(`${entry.key}: ${entry.title}`),
    description: entry.summary,
    path: `/e/${encodeURIComponent(entry.key)}`,
    origin,
  });
}

const OTHER_TABS: Record<EntryType, string[]> = {
  vuln: ['Exploitation', 'Affected and fixes', 'Timeline'],
  breach: ['Timeline', 'Sources'],
  ai: ['Timeline', 'Sources'],
  mal: ['Affected packages', 'Timeline'],
  tech: ['Related records'],
  term: [],
};

export default function Entry({ loaderData }: Route.ComponentProps) {
  const { entry, credits, origin } = loaderData;
  const nonce = useNonce();
  const tabs = OTHER_TABS[entry.type];
  return (
    <div className="entry-layout">
      <article>
        <nav className="crumbs" aria-label="Breadcrumb">
          <Link to="/">Home</Link>
          <span aria-hidden="true">/</span>
          <Link to={`/search?type=${entry.type}`}>{TYPE_PLURALS[entry.type]}</Link>
          <span aria-hidden="true">/</span>
          <span>{entry.key}</span>
        </nav>
        <header className="entry-head">
          <div className="entry-ids">
            <TypeBadge type={entry.type} />
            <span className="mono">{entry.key}</span>
            {entry.aliases.map((a) => (
              <Chip key={a}>{a}</Chip>
            ))}
          </div>
          <h1>{entry.title}</h1>
          <p className="muted">{entry.subtitle}</p>
          <div className="chips">
            {entry.kev_added ? <Chip tone="kev">Exploited in the wild</Chip> : null}
            {entry.type === 'vuln' && !entry.kev_added ? <Chip>Not on CISA KEV</Chip> : null}
            {entry.cvss !== null ? <Chip>CVSS {entry.cvss.toFixed(1)}</Chip> : null}
          </div>
        </header>

        <ul className="tabs" aria-label="Record sections">
          <li className="tab" aria-current="page">
            Overview
          </li>
          {tabs.map((t) => (
            <li key={t} className="tab">
              {t}
              <small>free account</small>
            </li>
          ))}
        </ul>

        <section aria-labelledby="summary-title">
          <h2 id="summary-title" className="label">
            Summary
          </h2>
          <p>{entry.summary}</p>
        </section>

        {entry.type === 'term' ? null : <GateCard entryKey={entry.key} />}
        <CreditList credits={credits} />
      </article>

      <aside className="panel glance" aria-labelledby="glance-title">
        <h2 id="glance-title">At a glance</h2>
        <dl>
          {entry.type === 'vuln' ? (
            <>
              <div>
                <dt className="label">CVSS</dt>
                <dd>
                  {entry.cvss === null ? (
                    'Not scored'
                  ) : (
                    <span className="cvss">
                      <span className="cvss-number">{entry.cvss.toFixed(1)}</span>
                      <CvssMeter score={entry.cvss} />
                    </span>
                  )}
                </dd>
              </div>
              <div>
                <dt className="label">CISA KEV</dt>
                <dd>{entry.kev_added ? `Added ${formatDate(entry.kev_added)}` : 'Not on the list'}</dd>
              </div>
              <div>
                <dt className="label">Published</dt>
                <dd>{formatDate(entry.published)}</dd>
              </div>
            </>
          ) : (
            <>
              {entry.published ? (
                <div>
                  <dt className="label">Date</dt>
                  <dd>{formatDate(entry.published)}</dd>
                </div>
              ) : null}
              <div>
                <dt className="label">About</dt>
                <dd>{entry.subtitle}</dd>
              </div>
            </>
          )}
          <div>
            <dt className="label">Coverage</dt>
            <dd>
              Built from {credits.length} {credits.length === 1 ? 'source' : 'sources'}
            </dd>
          </div>
        </dl>
      </aside>

      <JsonLd
        nonce={nonce}
        data={{
          '@context': 'https://schema.org',
          '@type': 'WebPage',
          name: `${entry.key}: ${entry.title}`,
          description: entry.summary,
          identifier: entry.key,
          url: new URL(`/e/${encodeURIComponent(entry.key)}`, origin).toString(),
          ...(entry.published ? { datePublished: entry.published } : {}),
        }}
      />
    </div>
  );
}
