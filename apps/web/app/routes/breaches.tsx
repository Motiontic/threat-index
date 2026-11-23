import { Link } from 'react-router';
import { CreditList, EmptyState } from '../components/ui';
import { WorldPager, WorldSearch } from '../components/world';
import { ApiBadRequest } from '../data/api.server';
import { getData } from '../data/data.server';
import type { BreachSummary, Credit } from '../data/types';
import { formatDate } from '../lib/format';
import { buildMeta, pageTitle } from '../lib/seo';
import { countLine, parseWorldParams, pluralise } from '../lib/world';
import type { Route } from './+types/breaches';

export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  const params = parseWorldParams(url.searchParams);
  const base = { origin: url.origin, params };
  try {
    const res = await getData(request).breaches(params);
    return { ...base, items: res.items, next: res.next, credits: res.credits };
  } catch (err) {
    // A bad query is shown as an empty list, not an error page.
    if (err instanceof ApiBadRequest)
      return { ...base, items: [] as BreachSummary[], next: null as number | null, credits: [] as Credit[] };
    throw err;
  }
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  const { params, origin } = loaderData;
  return buildMeta({
    title: pageTitle(params.q ? `Breaches: ${params.q}` : 'Breach notices'),
    description:
      'Public breach notices from regulators and breach databases, with each count kept in its own unit.',
    path: '/breaches',
    origin,
    noindex: params.page > 1 || Boolean(params.q),
  });
}

export default function Breaches({ loaderData }: Route.ComponentProps) {
  const { params, items, next, credits } = loaderData;
  return (
    <div>
      <div className="page-head">
        <h1>Breach notices</h1>
      </div>
      <WorldSearch action="/breaches" params={params} label="Search breaches by company" />
      {items.length === 0 ? (
        <EmptyState title="No matching breaches">
          <p>
            Try a company name or fewer words. <Link to="/breaches">Clear the search</Link>.
          </p>
        </EmptyState>
      ) : (
        <ul className="panel">
          {items.map((b) => (
            <li key={b.key} className="row">
              <span className="mono muted">{formatDate(b.firstSeen)}</span>
              <span className="row-main">
                <Link to={`/breach/${encodeURIComponent(b.key)}`}>{b.company?.name ?? b.key}</Link>
              </span>
              <span className="muted">
                {pluralise(b.noticeCount, 'notice')}
                {b.counts[0] ? ` · ${countLine(b.counts[0])}` : ''}
                {b.counts.length > 1 ? ` · +${b.counts.length - 1} more` : ''}
              </span>
            </li>
          ))}
        </ul>
      )}
      <WorldPager path="/breaches" params={params} page={params.page} next={next} />
      <CreditList credits={credits} />
    </div>
  );
}
