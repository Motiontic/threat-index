import { Form, Link } from 'react-router';
import { errorText, useAccountFetcher } from '../components/account-bits';
import { EmptyState, ResultCard } from '../components/ui';
import { ApiBadRequest } from '../data/api.server';
import { getData } from '../data/data.server';
import type { EntryType, SearchHit } from '../data/types';
import { useAuthState, useOpenSignUp } from '../lib/auth';
import { TYPE_PLURALS } from '../lib/format';
import { saveIntent } from '../lib/intent';
import { API_TYPES, hasCriteria, paramsToQuery, parseSearchParams, SEVERITIES } from '../lib/search-params';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/search';

type Outcome = 'results' | 'no-criteria' | 'not-indexed' | 'bad-request';

export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  const params = parseSearchParams(url.searchParams);
  const site = getData(request);
  const year = new Date().getUTCFullYear();
  const base = {
    origin: url.origin,
    params,
    mode: site.mode,
    years: Array.from({ length: 10 }, (_, i) => String(year - i)),
  };
  const empty = { total: 0, hits: [] as (SearchHit & { kind?: string })[], next: null as string | null };

  if (site.mode === 'api' && params.type && params.type.every((t) => !API_TYPES.includes(t)))
    return { ...base, outcome: 'not-indexed' as Outcome, ...empty };
  if (!hasCriteria(params)) return { ...base, outcome: 'no-criteria' as Outcome, ...empty };
  try {
    const res = await site.search(params);
    return {
      ...base,
      outcome: 'results' as Outcome,
      total: res.total,
      hits: res.hits as (SearchHit & { kind?: string })[],
      next: res.cursor ?? null,
    };
  } catch (err) {
    if (err instanceof ApiBadRequest) return { ...base, outcome: 'bad-request' as Outcome, ...empty };
    throw err;
  }
}

function heading(q: string | undefined, type: EntryType[] | undefined): string {
  if (q) return `Results for “${q}”`;
  if (type?.length === 1) return TYPE_PLURALS[type[0] as EntryType];
  return 'Everything';
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  const { params, origin } = loaderData;
  return buildMeta({
    title: pageTitle(heading(params.q, params.type)),
    description: 'Search results from the Threat Index.',
    path: '/search',
    origin,
    noindex: true,
  });
}

const TYPES = Object.keys(TYPE_PLURALS) as EntryType[];
const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' } as const;

export default function Search({ loaderData }: Route.ComponentProps) {
  const { params, total, hits, next, outcome, years } = loaderData;
  const type = params.type ?? [];
  const sort = params.sort ?? (params.q ? 'rel' : 'new');
  return (
    <div>
      <div className="page-head">
        <h1>{heading(params.q, params.type)}</h1>
        {outcome === 'results' ? (
          <span className="muted" aria-live="polite">
            {total} {total === 1 ? 'result' : 'results'}
          </span>
        ) : null}
        {hasCriteria(params) ? <SaveSearch qs={paramsToQuery(params, null)} /> : null}
      </div>
      <div className="search-layout">
        <Form method="get" action="/search" className="filters panel" aria-label="Filter results">
          <input type="hidden" name="q" value={params.q ?? ''} />
          <fieldset>
            <legend className="label">Type</legend>
            {TYPES.map((t) => (
              <label key={t} className="check">
                <input type="checkbox" name="type" value={t} defaultChecked={type.includes(t)} />
                {TYPE_PLURALS[t]}
              </label>
            ))}
          </fieldset>
          <fieldset>
            <legend className="label">Signal</legend>
            <label className="check">
              <input type="checkbox" name="sig" value="kev" defaultChecked={Boolean(params.sig)} />
              Exploited in the wild
            </label>
          </fieldset>
          <div>
            <label className="label" htmlFor="f-sev">
              Severity
            </label>
            <select id="f-sev" className="input" name="sev" defaultValue={params.sev ?? ''}>
              <option value="">Any</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABEL[s]}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="f-year">
              Year
            </label>
            <select id="f-year" className="input" name="year" defaultValue={params.year ?? ''}>
              <option value="">Any</option>
              {years.map((y) => (
                <option key={y} value={y}>
                  {y}
                </option>
              ))}
            </select>
          </div>
          <fieldset>
            <legend className="label">Sort</legend>
            <label className="check">
              <input type="radio" name="sort" value="rel" defaultChecked={sort === 'rel'} />
              Best match
            </label>
            <label className="check">
              <input type="radio" name="sort" value="new" defaultChecked={sort === 'new'} />
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
          {outcome === 'not-indexed' ? (
            <EmptyState title={`${type.map((t) => TYPE_PLURALS[t]).join(', ')} are not in the index yet`}>
              <p>
                Try <Link to="/search?type=vuln">vulnerabilities</Link> or{' '}
                <Link to="/search?type=mal">malicious packages</Link>.
              </p>
            </EmptyState>
          ) : outcome === 'no-criteria' ? (
            <EmptyState title="Add a word or an ID to search">
              <p>
                Or browse: <Link to="/search?type=vuln">vulnerabilities</Link>,{' '}
                <Link to="/search?sig=kev">exploited in the wild</Link>,{' '}
                <Link to="/index">the A–Z index</Link>.
              </p>
            </EmptyState>
          ) : outcome === 'bad-request' ? (
            <EmptyState title="Add a word or an ID to search" />
          ) : hits.length === 0 ? (
            <EmptyState title="No matching records">
              <p>
                Try a CVE ID, a product name or fewer filters. <Link to="/search">Clear the search</Link>.
              </p>
            </EmptyState>
          ) : (
            hits.map((h) => <ResultCard key={h.key} hit={h} />)
          )}
          {outcome === 'results' && (next || params.cursor) ? (
            <nav className="pager" aria-label="Pages">
              {params.cursor ? <Link to={`/search${paramsToQuery(params, null)}`}>First page</Link> : null}
              {next ? <Link to={`/search${paramsToQuery(params, next)}`}>Next page</Link> : null}
            </nav>
          ) : null}
        </div>
      </div>
    </div>
  );
}

/** Signed in: saves this search. Signed out: remembers the intent and opens the sign-up modal. */
function SaveSearch({ qs }: { qs: string }) {
  const { isSignedIn, available } = useAuthState();
  const open = useOpenSignUp();
  const { submit, busy, result } = useAccountFetcher();
  if (!available) return null;
  return (
    <span className="save-search">
      <button
        type="button"
        className="button"
        disabled={busy}
        onClick={() => {
          if (isSignedIn) return submit({ intent: 'save-search', qs });
          saveIntent({ action: 'save-search', target: qs });
          open({ fallbackRedirectUrl: window.location.href });
        }}
      >
        Save search
      </button>{' '}
      <span className="muted" role="status">
        {result ? (result.ok ? 'Search saved' : errorText(result.error)) : ''}
      </span>
    </span>
  );
}
