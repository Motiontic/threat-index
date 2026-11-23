import { data } from 'react-router';
import { Chip, CreditList, Panel, Table } from '../components/ui';
import { ApiBadRequest } from '../data/api.server';
import { getData } from '../data/data.server';
import type { BreachNotice } from '../data/types';
import { formatDate } from '../lib/format';
import { buildMeta, pageTitle } from '../lib/seo';
import { countLine, pluralise } from '../lib/world';
import type { Route } from './+types/breach';

const KEY_PATTERN = /^[\x20-\x7e]{1,200}$/;

export async function loader({ request, params }: Route.LoaderArgs) {
  const key = params.key ?? '';
  if (!KEY_PATTERN.test(key)) throw data(null, { status: 404 });
  let breach: Awaited<ReturnType<ReturnType<typeof getData>['breach']>>;
  try {
    breach = await getData(request).breach(key);
  } catch (err) {
    if (err instanceof ApiBadRequest) throw data(null, { status: 404 });
    throw err;
  }
  if (!breach) throw data(null, { status: 404 });
  return { origin: new URL(request.url).origin, breach };
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  const { breach, origin } = loaderData;
  const name = breach.company?.name ?? breach.key;
  return buildMeta({
    title: pageTitle(`Breach: ${name}`),
    description: `Breach notices for ${name}: ${pluralise(breach.noticeCount, 'notice')}, first reported ${breach.firstSeen}.`,
    path: `/breach/${encodeURIComponent(breach.key)}`,
    origin,
  });
}

function noticeCount(n: BreachNotice): string {
  if (n.count === undefined || !n.countUnit) return 'Count not stated';
  return countLine({ unit: n.countUnit, jurisdiction: n.jurisdiction ?? null, count: n.count });
}

export default function Breach({ loaderData }: Route.ComponentProps) {
  const { breach } = loaderData;
  const name = breach.company?.name ?? breach.key;
  return (
    <div>
      <div className="page-head">
        <h1>{name}</h1>
        <span className="muted">First reported {formatDate(breach.firstSeen)}</span>
      </div>
      <Panel title="At a glance">
        <dl>
          {breach.dates ? (
            <>
              <dt className="label">Dates</dt>
              <dd>
                {formatDate(breach.dates.from)} to {formatDate(breach.dates.to)}
              </dd>
            </>
          ) : null}
          <dt className="label">Counts</dt>
          <dd>
            {breach.counts.length === 0 ? (
              <p className="muted">No count in the notices we can show.</p>
            ) : (
              <ul>
                {breach.counts.map((c) => (
                  <li key={`${c.unit}-${c.jurisdiction ?? ''}`}>{countLine(c)}</li>
                ))}
              </ul>
            )}
            <p className="muted">
              Each count belongs to its own unit and place. They are never added together.
            </p>
          </dd>
          {breach.jurisdictions.length > 0 ? (
            <>
              <dt className="label">Jurisdictions</dt>
              <dd>{breach.jurisdictions.join(', ')}</dd>
            </>
          ) : null}
          <dt className="label">Notices</dt>
          <dd>{pluralise(breach.noticeCount, 'notice')}</dd>
        </dl>
      </Panel>
      <Table caption="Notices" head={['Notice', 'Date', 'Count', 'Source']}>
        {breach.notices.map((n) => (
          <tr key={`${n.source}-${n.noticeId}`}>
            <td>
              {n.name}
              {n.display === 'link' ? (
                <>
                  {' '}
                  <Chip>Link only</Chip>
                </>
              ) : null}
              {n.url ? (
                <>
                  <br />
                  <a href={n.url} rel="noopener noreferrer">
                    Read at source
                  </a>
                </>
              ) : null}
            </td>
            <td>{formatDate(n.notified)}</td>
            <td>{n.display === 'link' ? '' : noticeCount(n)}</td>
            <td className="mono">{n.source}</td>
          </tr>
        ))}
      </Table>
      <CreditList credits={breach.credits} />
    </div>
  );
}
