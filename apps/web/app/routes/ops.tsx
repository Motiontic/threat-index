import { env } from 'cloudflare:workers';
import { isAdmin, parseAdminIds } from '@ti/core/ops';
import { data } from 'react-router';
import { Chip, Panel, Table } from '../components/ui';
import { bridge, getAccount } from '../data/data.server';
import { formatDate } from '../lib/format';
import { buildMeta, pageTitle } from '../lib/seo';
import { siteOrigin } from '../lib/site.server';
import type { Route } from './+types/ops';

const NO_STORE = { 'Cache-Control': 'private, no-store' };

/** Signed out, not on this Worker's admin list, or refused by the API: all look like a missing page. */
export async function loader(args: Route.LoaderArgs) {
  const account = await getAccount(args);
  if (!account || !isAdmin(parseAdminIds(env.ADMIN_USER_IDS), account.session.userId))
    throw data(null, { status: 404 });
  const report = await bridge(() => account.client.adminOps());
  if (!report) throw data(null, { status: 404 });
  return data({ report, origin: siteOrigin(args.request) }, { headers: NO_STORE });
}

export const headers: Route.HeadersFunction = () => NO_STORE;

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Ops') }, { name: 'robots', content: 'noindex' }];
  return buildMeta({
    title: pageTitle('Ops'),
    description: 'Run health, budgets and queues.',
    path: '/ops',
    origin: loaderData.origin,
    noindex: true,
  });
}

const when = (iso: string | null) => (iso ? `${formatDate(iso)} ${iso.slice(11, 16)}Z` : 'never');
const num = (n: number) => n.toLocaleString('en-US');

function Meter({ label, value, max }: { label: string; value: number; max: number }) {
  const ratio = max > 0 ? Math.min(1, value / max) : 0;
  return (
    <div>
      <div>
        {label}: <strong>{num(value)}</strong> of {num(max)}
      </div>
      <svg
        width="160"
        height="8"
        viewBox="0 0 160 8"
        role="img"
        aria-label={`${label}: ${Math.round(ratio * 100)} percent used`}
      >
        <rect className="meter-track" width="160" height="8" rx="4" />
        <rect
          className={ratio >= 0.9 ? 'meter-fill-bad' : 'meter-fill'}
          width={Math.round(ratio * 160)}
          height="8"
          rx="4"
        />
      </svg>
    </div>
  );
}

export default function Ops({ loaderData }: Route.ComponentProps) {
  const { report } = loaderData;
  const b = report.budget;
  // Late and failing sources first, then the rest by id.
  const sources = [...report.sources].sort(
    (x, y) => Number(y.late) - Number(x.late) || y.failed7d - x.failed7d || x.id.localeCompare(y.id),
  );
  return (
    <div>
      <div className="page-head">
        <h1>Ops</h1>
        <span className="muted">Generated {when(report.generatedAt)}</span>
      </div>
      <Panel title={`Budgets for ${b.day} (UTC)`}>
        <Meter label="D1 rows written" value={b.d1Writes} max={b.d1Limit} />
        <Meter label="Emails sent" value={b.emailsSent} max={b.emailCap} />
        <p className="muted">
          Queue operations recorded: {num(b.queueOps)}. R2 class A operations recorded: {num(b.r2ClassA)}.
        </p>
      </Panel>
      <Panel title="Queues">
        <Table caption="Queue backlogs" head={['Queue', 'Backlog', 'Oldest message']}>
          {report.queues.map((q) => (
            <tr key={q.name}>
              <td className="mono">{q.name}</td>
              <td>{q.backlog === null ? 'unknown' : num(q.backlog)}</td>
              <td>{q.oldest ? when(q.oldest) : '-'}</td>
            </tr>
          ))}
        </Table>
      </Panel>
      <Panel title={`Sources (${sources.length})`}>
        <Table
          caption="Sources, late and failing first"
          head={['Source', 'Cadence', 'Ingest', 'Last success', 'Last run', 'Failed 7d', 'Dead-lettered 7d']}
        >
          {sources.map((s) => (
            <tr key={s.id}>
              <td className="mono">
                {s.id} {s.late ? <Chip tone="bad">late</Chip> : null}
              </td>
              <td>{s.cadence}</td>
              <td>{s.ingest ? 'on' : 'off'}</td>
              <td>{when(s.lastSuccess)}</td>
              <td>{s.lastRun ? `${s.lastRun.status}, ${when(s.lastRun.startedAt)}` : '-'}</td>
              <td>{s.failed7d > 0 ? <Chip tone="warn">{s.failed7d}</Chip> : 0}</td>
              <td>{s.deadLettered7d > 0 ? <Chip tone="bad">{s.deadLettered7d}</Chip> : 0}</td>
            </tr>
          ))}
        </Table>
      </Panel>
      <Panel title={`Dead letters (${report.deadLetters.length})`}>
        {report.deadLetters.length === 0 ? (
          <p className="muted">None.</p>
        ) : (
          <Table caption="Dead-lettered runs" head={['Run', 'Source', 'Finished', 'Error']}>
            {report.deadLetters.map((d) => (
              <tr key={d.runId}>
                <td className="mono">{d.runId}</td>
                <td className="mono">{d.sourceId}</td>
                <td>{when(d.finishedAt)}</td>
                <td>{d.error}</td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
      <Panel title="E2B jobs, last 7 days">
        <p className="muted">
          {Object.entries(report.jobs.byStatus)
            .map(([status, n]) => `${status}: ${num(n)}`)
            .join(' · ') || 'No jobs.'}
        </p>
        {report.jobs.recent.length === 0 ? null : (
          <Table caption="Newest jobs" head={['Job', 'Kind', 'Status', 'Source', 'Created', 'Error']}>
            {report.jobs.recent.map((j) => (
              <tr key={j.id}>
                <td className="mono">{j.id}</td>
                <td>{j.kind}</td>
                <td>{j.status}</td>
                <td className="mono">{j.sourceId ?? '-'}</td>
                <td>{when(j.createdAt)}</td>
                <td>{j.error ?? ''}</td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
