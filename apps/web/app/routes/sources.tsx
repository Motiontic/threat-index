import { Link } from 'react-router';
import { Table } from '../components/ui';
import { getData } from '../data/data.server';
import type { SourceStatus } from '../data/types';
import { formatDate } from '../lib/format';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/sources';

type LicenceFilter = SourceStatus['licence'];

export const WAY_IN: Record<string, string> = {
  git: 'Git repository',
  changelist: 'Change list',
  since: 'API, changes since last run',
  fingerprint: 'Data file, checked for changes',
  feed: 'RSS or Atom feed',
  page: 'Web page',
  heavy: 'Large file, handled off-Worker',
};

export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  const site = getData(request);
  const { sources } = await site.sources();
  const wanted = url.searchParams.get('status');
  const status = (['on', 'ask', 'wait', 'link'] as const).find((s) => s === wanted) ?? null;
  const counts = { all: sources.length, on: 0, ask: 0, wait: 0, link: 0 };
  for (const s of sources) counts[s.licence] += 1;
  return {
    origin: url.origin,
    sample: site.mode === 'fixtures',
    status,
    counts,
    rows: status ? sources.filter((s) => s.licence === status) : sources,
  };
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  return buildMeta({
    title: pageTitle('Sources'),
    description: 'Every public source behind Threat Index, with how it is fetched and its licence status.',
    path: '/sources',
    origin: loaderData.origin,
  });
}

/** `7 Apr 2025, 09:00 UTC` */
function formatDateTime(iso: string | undefined): string {
  if (!iso) return 'Never';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return 'Never';
  return `${formatDate(d)}, ${d.toISOString().slice(11, 16)} UTC`;
}

const STATUS_LABEL: Record<LicenceFilter, string> = {
  on: 'On',
  ask: 'On · asked to be safe',
  wait: 'Off until written OK',
  link: 'Link-only until OK',
};
const STATUS_TONE: Record<LicenceFilter, string> = {
  on: 'chip chip-ok',
  ask: 'chip chip-warn',
  wait: 'chip chip-bad',
  link: 'chip',
};

export default function Sources({ loaderData }: Route.ComponentProps) {
  const { status, counts, rows, sample } = loaderData;
  const filters: { key: LicenceFilter | null; label: string; count: number }[] = [
    { key: null, label: 'All', count: counts.all },
    { key: 'on', label: STATUS_LABEL.on, count: counts.on },
    { key: 'ask', label: STATUS_LABEL.ask, count: counts.ask },
    { key: 'wait', label: STATUS_LABEL.wait, count: counts.wait },
    { key: 'link', label: STATUS_LABEL.link, count: counts.link },
  ];
  return (
    <div>
      <div className="page-head">
        <h1>Sources</h1>
        <span className="muted">
          {rows.length} of {counts.all} sources.{sample ? ' Last-success times are samples.' : ''}
        </span>
      </div>
      <nav className="filter-bar" aria-label="Filter by licence status">
        {filters.map((f) => (
          <Link
            key={f.label}
            className="pill"
            to={f.key ? `/sources?status=${f.key}` : '/sources'}
            aria-current={f.key === status ? 'page' : undefined}
          >
            {f.label} <span className="num">{f.count}</span>
          </Link>
        ))}
      </nav>
      <Table
        caption="Sources"
        head={[
          'Source',
          'What it gives',
          'Way in',
          'Cadence',
          sample ? 'Last success (sample)' : 'Last success',
          'Last run',
          'Licence',
        ]}
      >
        {rows.map((r) => (
          <tr key={r.id}>
            <th scope="row">{r.name}</th>
            <td>{r.gives}</td>
            <td>{WAY_IN[r.pattern] ?? r.pattern}</td>
            <td className="mono">{r.cadence}</td>
            <td className="num">{formatDateTime(r.lastSuccess)}</td>
            <td>{r.lastRunStatus ?? ''}</td>
            <td>
              <span className={STATUS_TONE[r.licence]}>{STATUS_LABEL[r.licence]}</span>
            </td>
          </tr>
        ))}
      </Table>
    </div>
  );
}
