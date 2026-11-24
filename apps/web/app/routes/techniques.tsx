import { Link } from 'react-router';
import { Chip, CreditList, EmptyState, NoRecords } from '../components/ui';
import { FilterChips, WorldPager, WorldSearch } from '../components/world';
import { ApiBadRequest } from '../data/api.server';
import { getData } from '../data/data.server';
import type { Credit, TechniqueSummary } from '../data/types';
import { buildMeta, pageTitle } from '../lib/seo';
import { siteOrigin } from '../lib/site.server';
import { FRAMEWORK_LABELS, FRAMEWORKS, parseWorldParams } from '../lib/world';
import type { Route } from './+types/techniques';

export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  const params = parseWorldParams(url.searchParams, { framework: FRAMEWORKS });
  const base = { origin: siteOrigin(request), params };
  try {
    const res = await getData(request).techniques(params);
    return { ...base, items: res.items, next: res.next, credits: res.credits };
  } catch (err) {
    if (err instanceof ApiBadRequest)
      return {
        ...base,
        items: [] as TechniqueSummary[],
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
    title: pageTitle('Techniques and weaknesses'),
    description: 'ATT&CK and ATLAS techniques, CAPEC attack patterns and CWE weaknesses.',
    path: '/techniques',
    origin,
    noindex: params.page > 1 || Boolean(params.q) || Boolean(params.framework),
  });
}

export default function Techniques({ loaderData }: Route.ComponentProps) {
  const { params, items, next, credits } = loaderData;
  return (
    <div>
      <div className="page-head">
        <h1>Techniques and weaknesses</h1>
      </div>
      <WorldSearch action="/techniques" params={params} label="Search techniques by ID or name" />
      <FilterChips
        path="/techniques"
        field="framework"
        params={params}
        chips={[
          { label: 'All', values: [] },
          ...FRAMEWORKS.map((f) => ({ label: FRAMEWORK_LABELS[f], values: [f] })),
        ]}
      />
      {items.length === 0 && !params.q && params.page === 1 ? (
        <NoRecords what="techniques" />
      ) : items.length === 0 ? (
        <EmptyState title="No matching techniques">
          <p>
            Try an ID such as T1190 or fewer words. <Link to="/techniques">Clear the search</Link>.
          </p>
        </EmptyState>
      ) : (
        <ul className="panel">
          {items.map((t) => (
            <li key={t.id} className="row">
              <span className="mono muted">{t.id}</span>
              <span className="row-main">
                <Link to={`/technique/${encodeURIComponent(t.id)}`}>{t.name}</Link>
              </span>
              <Chip>{FRAMEWORK_LABELS[t.framework]}</Chip>
            </li>
          ))}
        </ul>
      )}
      <WorldPager path="/techniques" params={params} page={params.page} next={next} />
      <CreditList credits={credits} />
    </div>
  );
}
