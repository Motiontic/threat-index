import { data, Link } from 'react-router';
import { Chip, CreditList, EmptyState, Panel } from '../components/ui';
import { ApiBadRequest } from '../data/api.server';
import { getData } from '../data/data.server';
import { buildMeta, pageTitle } from '../lib/seo';
import { FRAMEWORK_LABELS } from '../lib/world';
import type { Route } from './+types/technique';

const ID_PATTERN = /^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?|CWE-\d{1,6}|CAPEC-\d{1,6})$/;

export async function loader({ request, params }: Route.LoaderArgs) {
  const id = params.id ?? '';
  if (!ID_PATTERN.test(id)) throw data(null, { status: 404 });
  let technique: Awaited<ReturnType<ReturnType<typeof getData>['technique']>>;
  try {
    technique = await getData(request).technique(id);
  } catch (err) {
    if (err instanceof ApiBadRequest) throw data(null, { status: 404 });
    throw err;
  }
  if (!technique) throw data(null, { status: 404 });
  return { origin: new URL(request.url).origin, technique };
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  const { technique, origin } = loaderData;
  return buildMeta({
    title: pageTitle(`${technique.id}: ${technique.name}`),
    description:
      technique.summary ?? `${FRAMEWORK_LABELS[technique.framework]} ${technique.id}: ${technique.name}.`,
    path: `/technique/${encodeURIComponent(technique.id)}`,
    origin,
  });
}

export default function Technique({ loaderData }: Route.ComponentProps) {
  const { technique: t } = loaderData;
  return (
    <div>
      <div className="page-head">
        <h1>
          <span className="mono">{t.id}</span> {t.name}
        </h1>
        <Chip>{FRAMEWORK_LABELS[t.framework]}</Chip>
      </div>
      {t.summary ? <p>{t.summary}</p> : null}
      {t.parentRef ? (
        <p>
          Part of{' '}
          <Link to={`/technique/${encodeURIComponent(t.parentRef.id)}`}>
            <span className="mono">{t.parentRef.id}</span> {t.parentRef.name}
          </Link>
        </p>
      ) : null}
      {t.children.length > 0 ? (
        <Panel title="Sub-techniques">
          <ul>
            {t.children.map((c) => (
              <li key={c.id} className="row">
                <span className="mono muted">{c.id}</span>
                <span className="row-main">
                  <Link to={`/technique/${encodeURIComponent(c.id)}`}>{c.name}</Link>
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}
      <Panel title="Linked vulnerabilities">
        {t.vulns.length === 0 ? (
          <EmptyState title="No linked vulnerabilities yet" />
        ) : (
          <ul>
            {t.vulns.map((v) => (
              <li key={v.key} className="row">
                <span className="mono muted">{v.key}</span>
                <span className="row-main">
                  <Link to={`/e/${encodeURIComponent(v.key)}`}>{v.title}</Link>
                </span>
                {v.exploited ? <Chip tone="kev">Exploited</Chip> : null}
                {v.cvss !== undefined ? <Chip>CVSS {v.cvss.toFixed(1)}</Chip> : null}
              </li>
            ))}
          </ul>
        )}
        {t.vulnsMore ? <p className="muted">More linked vulnerabilities exist than are shown here.</p> : null}
      </Panel>
      <CreditList credits={t.credits} />
    </div>
  );
}
