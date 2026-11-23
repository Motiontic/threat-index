import { Form, Link } from 'react-router';
import { EmptyState, ResultCard } from '../components/ui';
import { getData, MAX_QUERY } from '../data/data.server';
import type { EntryType } from '../data/types';
import { TYPE_PLURALS } from '../lib/format';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/search';

export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  const sortParam = url.searchParams.get('sort');
  const result = getData(request).search({
    q: (url.searchParams.get('q') ?? '').slice(0, MAX_QUERY),
    type: url.searchParams.getAll('type'),
    sig: url.searchParams.getAll('sig'),
    ...(sortParam === 'rel' || sortParam === 'new' ? { sort: sortParam } : {}),
  });
  return { origin: url.origin, ...result };
}

function heading(q: string, type: string[]): string {
  if (q) return `Results for “${q}”`;
  if (type.length === 1) return TYPE_PLURALS[type[0] as EntryType];
  return 'Everything';
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  const { params, origin } = loaderData;
  return buildMeta({
    title: pageTitle(heading(params.q, params.type)),
    description: 'Search results from the Threat Index sample records.',
    path: '/search',
    origin,
    noindex: true,
  });
}

const TYPES = Object.keys(TYPE_PLURALS) as EntryType[];

export default function Search({ loaderData }: Route.ComponentProps) {
  const { params, total, results } = loaderData;
  return (
    <div>
      <div className="page-head">
        <h1>{heading(params.q, params.type)}</h1>
        <span className="muted" aria-live="polite">
          {total} {total === 1 ? 'result' : 'results'}
          {total > results.length ? `, showing the first ${results.length}` : ''}
        </span>
      </div>
      <div className="search-layout">
        <Form method="get" action="/search" className="filters panel" aria-label="Filter results">
          <input type="hidden" name="q" value={params.q} />
          <fieldset>
            <legend className="label">Type</legend>
            {TYPES.map((t) => (
              <label key={t} className="check">
                <input type="checkbox" name="type" value={t} defaultChecked={params.type.includes(t)} />
                {TYPE_PLURALS[t]}
              </label>
            ))}
          </fieldset>
          <fieldset>
            <legend className="label">Signal</legend>
            <label className="check">
              <input type="checkbox" name="sig" value="kev" defaultChecked={params.sig.includes('kev')} />
              Exploited in the wild
            </label>
          </fieldset>
          <fieldset>
            <legend className="label">Sort</legend>
            <label className="check">
              <input type="radio" name="sort" value="rel" defaultChecked={params.sort === 'rel'} />
              Best match
            </label>
            <label className="check">
              <input type="radio" name="sort" value="new" defaultChecked={params.sort === 'new'} />
              Newest
            </label>
          </fieldset>
          <div className="filter-actions">
            <button type="submit" className="button button-primary">
              Apply
            </button>
            <Link to={params.q ? `/search?q=${encodeURIComponent(params.q)}` : '/search'} className="button">
              Clear
            </Link>
          </div>
        </Form>
        <div>
          {results.length === 0 ? (
            <EmptyState title="No matching records">
              <p>
                Try a CVE ID, a product name or fewer filters. <Link to="/search">Clear the search</Link>.
              </p>
            </EmptyState>
          ) : (
            results.map((e) => <ResultCard key={e.key} entry={e} />)
          )}
        </div>
      </div>
    </div>
  );
}
