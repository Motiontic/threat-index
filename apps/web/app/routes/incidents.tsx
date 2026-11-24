import { Link } from 'react-router';
import { Chip, CreditList, EmptyState, NoRecords } from '../components/ui';
import { FilterChips, WorldPager, WorldSearch } from '../components/world';
import { ApiBadRequest } from '../data/api.server';
import { getData } from '../data/data.server';
import type { Credit, IncidentSummary } from '../data/types';
import { formatDate } from '../lib/format';
import { buildMeta, pageTitle } from '../lib/seo';
import { siteOrigin } from '../lib/site.server';
import { INCIDENT_KINDS, KIND_LABELS, parseWorldParams } from '../lib/world';
import type { Route } from './+types/incidents';

export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  const params = parseWorldParams(url.searchParams, { kind: INCIDENT_KINDS });
  const base = { origin: siteOrigin(request), params };
  try {
    const res = await getData(request).incidents(params);
    return { ...base, items: res.items, next: res.next, credits: res.credits };
  } catch (err) {
    if (err instanceof ApiBadRequest)
      return {
        ...base,
        items: [] as IncidentSummary[],
        next: null as number | null,
        credits: [] as Credit[],
      };
    throw err;
  }
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  const { params, origin } = loaderData;
  return buildMeta({
    title: pageTitle('Incidents'),
    description: 'AI incidents, cyber operations and cyber events, with a link to each source.',
    path: '/incidents',
    origin,
    noindex: params.page > 1 || Boolean(params.q) || Boolean(params.kind),
  });
}

/** What an unfiltered-by-query empty list is called: the kind chip that is selected, or all incidents. */
function noRecordsWhat(kind: string[] | undefined): string {
  if (kind?.length === 1 && kind[0] === 'ai') return 'AI incidents';
  if (kind?.length && kind.every((k) => k.startsWith('cyber'))) return 'cyber operations or events';
  return 'incidents';
}

export default function Incidents({ loaderData }: Route.ComponentProps) {
  const { params, items, next, credits } = loaderData;
  return (
    <div>
      <div className="page-head">
        <h1>Incidents</h1>
      </div>
      <WorldSearch action="/incidents" params={params} label="Search incidents by title" />
      <FilterChips
        path="/incidents"
        field="kind"
        params={params}
        chips={[
          { label: 'All', values: [] },
          { label: 'AI incidents', values: ['ai'] },
          { label: 'Cyber operations and events', values: ['cyber'] },
        ]}
      />
      {items.length === 0 && !params.q && params.page === 1 ? (
        <NoRecords what={noRecordsWhat(params.kind)} />
      ) : items.length === 0 ? (
        <EmptyState title="No matching incidents">
          <p>
            Try fewer words. <Link to="/incidents">Clear the search</Link>.
          </p>
        </EmptyState>
      ) : (
        <ul className="panel">
          {items.map((i) => (
            <li key={`${i.source}-${i.incidentId}`} className="row">
              <span className="mono muted">{formatDate(i.date)}</span>
              <span className="row-main">
                <Link to={`/incident/${encodeURIComponent(i.source)}/${encodeURIComponent(i.incidentId)}`}>
                  {i.title}
                </Link>
              </span>
              <Chip>{KIND_LABELS[i.kind]}</Chip>
            </li>
          ))}
        </ul>
      )}
      <WorldPager path="/incidents" params={params} page={params.page} next={next} />
      <CreditList credits={credits} />
    </div>
  );
}
