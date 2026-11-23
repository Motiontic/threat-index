import { data, Link } from 'react-router';
import { Chip, CreditList, Panel } from '../components/ui';
import { ApiBadRequest } from '../data/api.server';
import { getData } from '../data/data.server';
import { formatDate } from '../lib/format';
import { buildMeta, pageTitle } from '../lib/seo';
import { KIND_LABELS } from '../lib/world';
import type { Route } from './+types/incident';

const SOURCE_PATTERN = /^[a-z0-9-]{1,64}$/;
const ID_PATTERN = /^[\x20-\x7e]{1,200}$/;

export async function loader({ request, params }: Route.LoaderArgs) {
  const { source = '', id = '' } = params;
  if (!SOURCE_PATTERN.test(source) || !ID_PATTERN.test(id)) throw data(null, { status: 404 });
  let incident: Awaited<ReturnType<ReturnType<typeof getData>['incident']>>;
  try {
    incident = await getData(request).incident(source, id);
  } catch (err) {
    if (err instanceof ApiBadRequest) throw data(null, { status: 404 });
    throw err;
  }
  if (!incident) throw data(null, { status: 404 });
  return { origin: new URL(request.url).origin, incident };
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  const { incident, origin } = loaderData;
  const when = incident.date ? `, dated ${incident.date}` : '';
  return buildMeta({
    title: pageTitle(incident.title),
    description: `${KIND_LABELS[incident.kind]}: ${incident.title}${when}.`,
    path: `/incident/${encodeURIComponent(incident.source)}/${encodeURIComponent(incident.incidentId)}`,
    origin,
  });
}

export default function Incident({ loaderData }: Route.ComponentProps) {
  const { incident } = loaderData;
  return (
    <div>
      <div className="page-head">
        <h1>{incident.title}</h1>
        <Chip>{KIND_LABELS[incident.kind]}</Chip>
        {incident.display === 'link' ? <Chip>Link only</Chip> : null}
      </div>
      <Panel title="Details">
        <dl>
          {incident.date ? (
            <>
              <dt className="label">Date</dt>
              <dd>{formatDate(incident.date)}</dd>
            </>
          ) : null}
          {incident.entities.length > 0 ? (
            <>
              <dt className="label">Entities</dt>
              <dd>{incident.entities.join(', ')}</dd>
            </>
          ) : null}
          {incident.techniques.length > 0 ? (
            <>
              <dt className="label">Techniques</dt>
              <dd>
                <ul>
                  {incident.techniques.map((t) => (
                    <li key={t.id}>
                      <Link to={`/technique/${encodeURIComponent(t.id)}`}>
                        <span className="mono">{t.id}</span>
                        {t.name ? ` ${t.name}` : ''}
                      </Link>
                    </li>
                  ))}
                </ul>
              </dd>
            </>
          ) : null}
          {incident.url ? (
            <>
              <dt className="label">Source</dt>
              <dd>
                <a href={incident.url} rel="noopener noreferrer">
                  Read at source
                </a>
              </dd>
            </>
          ) : null}
        </dl>
      </Panel>
      <CreditList credits={incident.credits} />
    </div>
  );
}
