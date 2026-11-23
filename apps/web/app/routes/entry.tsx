import { data, Link, redirect } from 'react-router';
import { Chip, CreditList, CvssMeter, GateCard, TypeBadge } from '../components/ui';
import { ApiBadRequest } from '../data/api.server';
import { getData } from '../data/data.server';
import { displayType } from '../data/display';
import type { EntryType } from '../data/types';
import { formatDate, TYPE_PLURALS } from '../lib/format';
import { useNonce } from '../lib/nonce';
import { buildMeta, JsonLd, pageTitle } from '../lib/seo';
import type { Route } from './+types/entry';

const ID_PATTERN = /^[A-Za-z0-9._:-]+$/;

export async function loader({ request, params }: Route.LoaderArgs) {
  const id = params.id ?? '';
  if (id.length > 100 || !ID_PATTERN.test(id)) throw data(null, { status: 404 });
  let entry: Awaited<ReturnType<ReturnType<typeof getData>['entry']>>;
  try {
    entry = await getData(request).entry(id);
  } catch (err) {
    if (err instanceof ApiBadRequest) throw data(null, { status: 404 });
    throw err;
  }
  if (!entry) throw data(null, { status: 404 });
  // Another case or an alias goes to the one canonical address.
  if (entry.key !== id) throw redirect(`/e/${encodeURIComponent(entry.key)}`, 301);
  return { origin: new URL(request.url).origin, entry };
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
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
  const { entry, origin } = loaderData;
  const nonce = useNonce();
  const type = displayType(entry.kind, entry.key);
  const tabs = OTHER_TABS[type];
  const credits = entry.credits;
  return (
    <div className="entry-layout">
      <article>
        <nav className="crumbs" aria-label="Breadcrumb">
          <Link to="/">Home</Link>
          <span aria-hidden="true">/</span>
          <Link to={`/search?type=${type}`}>{TYPE_PLURALS[type]}</Link>
          <span aria-hidden="true">/</span>
          <span>{entry.key}</span>
        </nav>
        <header className="entry-head">
          <div className="entry-ids">
            <TypeBadge type={type} />
            <span className="mono">{entry.key}</span>
            {entry.aliases.map((a) => (
              <Chip key={a}>{a}</Chip>
            ))}
          </div>
          <h1>{entry.title}</h1>
          <div className="chips">
            {entry.exploited ? <Chip tone="kev">Exploited in the wild</Chip> : null}
            {type === 'vuln' && !entry.exploited ? <Chip>Not on CISA KEV</Chip> : null}
            {entry.cvss !== undefined ? (
              <Chip>
                CVSS {entry.cvss.toFixed(1)}
                {entry.cvssVersion ? ` (v${entry.cvssVersion.replace(/^v/i, '')})` : ''}
              </Chip>
            ) : null}
          </div>
        </header>

        <ul className="tabs" aria-label="Record sections">
          <li>
            <Link className="tab" to={`/e/${encodeURIComponent(entry.key)}`} aria-current="page">
              Overview
            </Link>
          </li>
          {tabs.map((t) => (
            <li key={t}>
              <button type="button" className="tab tab-locked" disabled>
                {t}
                <small aria-hidden="true">free account</small>
                <span className="visually-hidden"> (needs a free account)</span>
              </button>
            </li>
          ))}
        </ul>

        <section aria-labelledby="summary-title">
          <h2 id="summary-title" className="label">
            Summary
          </h2>
          <p>{entry.summary}</p>
        </section>

        {type === 'term' ? null : <GateCard entryKey={entry.key} />}
        <CreditList credits={credits} />
      </article>

      <aside className="panel glance" aria-labelledby="glance-title">
        <h2 id="glance-title">At a glance</h2>
        <dl>
          <div>
            <dt className="label">CVSS</dt>
            <dd>
              {entry.cvss === undefined ? (
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
            <dd>{entry.kevAdded ? `Added ${formatDate(entry.kevAdded)}` : 'Not on the list'}</dd>
          </div>
          {entry.epss === undefined ? null : (
            <div>
              <dt className="label">EPSS</dt>
              <dd>{`${(entry.epss * 100).toFixed(entry.epss >= 0.1 ? 0 : 1)}%`}</dd>
            </div>
          )}
          {entry.published ? (
            <div>
              <dt className="label">Published</dt>
              <dd>{formatDate(entry.published)}</dd>
            </div>
          ) : null}
          {entry.modified ? (
            <div>
              <dt className="label">Modified</dt>
              <dd>{formatDate(entry.modified)}</dd>
            </div>
          ) : null}
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
          ...(entry.modified ? { dateModified: entry.modified } : {}),
        }}
      />
    </div>
  );
}
