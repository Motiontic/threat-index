import { PRODUCT_SHORT } from '@ti/core/brand';
import { data, Link } from 'react-router';
import { CompactRow, EmptyState, LetterBar } from '../components/ui';
import { ApiBadRequest } from '../data/api.server';
import { getData } from '../data/data.server';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/index-az';

export async function loader({ request, params }: Route.LoaderArgs) {
  const letter = params.letter ?? null;
  if (letter !== null && !/^[a-z0]$/.test(letter)) throw data(null, { status: 404 });
  const base = { origin: new URL(request.url).origin, letter };
  if (letter === null)
    return { ...base, items: [], next: null as string | null, cursor: null as string | null };
  const raw = new URL(request.url).searchParams.get('cursor');
  const cursor = raw && /^[A-Za-z0-9_-]{1,200}$/.test(raw) ? raw : null;
  try {
    const res = await getData(request).index(letter, cursor ?? undefined);
    return { ...base, items: res?.items ?? [], next: res?.cursor ?? null, cursor };
  } catch (err) {
    // A well-formed but invalid or expired cursor: show the empty state, with a "First page" link.
    if (err instanceof ApiBadRequest) return { ...base, items: [], next: null as string | null, cursor };
    throw err;
  }
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  const { letter, origin } = loaderData;
  const name = letter === null ? 'Index A–Z' : `Index: ${letter === '0' ? '0–9' : letter.toUpperCase()}`;
  return buildMeta({
    title: pageTitle(name),
    description: `Every entry in ${PRODUCT_SHORT}, listed alphabetically by ID.`,
    noindex: loaderData.letter !== null && loaderData.items.length === 0,
    path: letter === null ? '/index' : `/index/${letter}`,
    origin,
  });
}

export default function IndexAz({ loaderData }: Route.ComponentProps) {
  const { letter, items, next, cursor } = loaderData;
  return (
    <div>
      <div className="page-head">
        <h1>{letter === null ? 'Index A–Z' : `Index: ${letter === '0' ? '0–9' : letter.toUpperCase()}`}</h1>
        {letter === null ? null : <Link to="/index">Show all</Link>}
      </div>
      <LetterBar current={letter} />
      {letter === null ? (
        <p className="muted">Pick a letter to list the entries whose ID starts with it.</p>
      ) : items.length === 0 ? (
        <EmptyState title="Nothing under this letter yet" />
      ) : (
        <section className="index-group" aria-label="Entries">
          <ul className="panel">
            {items.map((e) => (
              <CompactRow key={e.key} item={e} />
            ))}
          </ul>
        </section>
      )}
      {letter !== null && (next || cursor) ? (
        <nav className="pager" aria-label="Pages">
          {cursor ? <Link to={`/index/${letter}`}>First page</Link> : null}
          {next ? <Link to={`/index/${letter}?cursor=${encodeURIComponent(next)}`}>Next page</Link> : null}
        </nav>
      ) : null}
    </div>
  );
}
