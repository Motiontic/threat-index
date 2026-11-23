import { data, Link } from 'react-router';
import { CompactRow, EmptyState, LetterBar } from '../components/ui';
import { getData } from '../data/data.server';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/index-az';

export async function loader({ request, params }: Route.LoaderArgs) {
  const letter = params.letter ?? null;
  if (letter !== null && !/^[a-z0]$/.test(letter)) throw data(null, { status: 404 });
  const all = getData(request).index(null);
  const shown = letter === null ? all : getData(request).index(letter);
  return {
    origin: new URL(request.url).origin,
    letter,
    counts: Object.fromEntries(all.buckets.map((b) => [b.letter, b.count])),
    buckets: shown.buckets.filter((b) => b.count > 0),
  };
}

export function meta({ loaderData }: Route.MetaArgs) {
  const { letter, origin } = loaderData;
  const name = letter === null ? 'Index A–Z' : `Index: ${letter === '0' ? '0–9' : letter.toUpperCase()}`;
  return buildMeta({
    title: pageTitle(name),
    description: 'Every entry in the Threat Index, listed alphabetically by ID.',
    path: letter === null ? '/index' : `/index/${letter}`,
    origin,
  });
}

export default function IndexAz({ loaderData }: Route.ComponentProps) {
  const { letter, counts, buckets } = loaderData;
  return (
    <div>
      <div className="page-head">
        <h1>{letter === null ? 'Index A–Z' : `Index: ${letter === '0' ? '0–9' : letter.toUpperCase()}`}</h1>
        {letter === null ? null : <Link to="/index">Show all</Link>}
      </div>
      <LetterBar counts={counts} current={letter} />
      {buckets.length === 0 ? (
        <EmptyState title="Nothing under this letter yet" />
      ) : (
        buckets.map((b) => (
          <section key={b.letter} className="index-group" aria-labelledby={`g-${b.letter}`}>
            <h2 id={`g-${b.letter}`}>
              {b.letter === '0' ? '0–9' : b.letter} <span className="muted">{b.count}</span>
            </h2>
            <ul className="panel">
              {b.entries.map((e) => (
                <CompactRow key={e.key} entry={e} />
              ))}
            </ul>
          </section>
        ))
      )}
    </div>
  );
}
