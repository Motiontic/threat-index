import { Link } from 'react-router';
import { Table } from '../components/ui';
import { getData } from '../data/data.server';
import type { LicenceFilter } from '../data/types';
import { formatDate } from '../lib/format';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/sources';

export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  return { origin: url.origin, ...getData(request).sources(url.searchParams.get('status')) };
}

export function meta({ loaderData }: Route.MetaArgs) {
  return buildMeta({
    title: pageTitle('Sources'),
    description: 'Every public source behind Threat Index, with how it is fetched and its licence status.',
    path: '/sources',
    origin: loaderData.origin,
  });
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
  const { status, counts, rows } = loaderData;
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
          {rows.length} of {counts.all} sources. Last-success times are samples.
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
        head={['Source', 'What it gives', 'Way in', 'Cadence', 'Last success (sample)', 'Status']}
      >
        {rows.map((r) => (
          <tr key={r.id}>
            <th scope="row">{r.name}</th>
            <td>{r.gives}</td>
            <td>{r.wayIn}</td>
            <td className="mono">{r.cadence}</td>
            <td className="num">{r.lastSuccess ? formatDate(r.lastSuccess) : '–'}</td>
            <td>
              <span className={STATUS_TONE[r.licence]}>{STATUS_LABEL[r.licence]}</span>
            </td>
          </tr>
        ))}
      </Table>
    </div>
  );
}
