import { useEffect, useRef } from 'react';
import { data, Link, redirect, useSearchParams } from 'react-router';
import { errorText, useAccountFetcher } from '../components/account-bits';
import { Chip, CreditList, CvssMeter, GateCard, TabBar, TypeBadge } from '../components/ui';
import { ApiBadRequest, SignInRequired } from '../data/api.server';
import { bridge, getAccount, getData } from '../data/data.server';
import { displayType } from '../data/display';
import type { EntryFullView } from '../data/types';
import { useAuthState, useOpenSignUp } from '../lib/auth';
import { groupEvidence } from '../lib/evidence';
import { formatDate, TYPE_PLURALS } from '../lib/format';
import { saveIntent } from '../lib/intent';
import { useNonce } from '../lib/nonce';
import { buildMeta, JsonLd, pageTitle, SITE_NAME } from '../lib/seo';
import { siteOrigin } from '../lib/site.server';
import type { Route } from './+types/entry';

const ID_PATTERN = /^[A-Za-z0-9._:-]+$/;

export async function loader(args: Route.LoaderArgs) {
  const { request, params } = args;
  const id = params.id ?? '';
  if (id.length > 100 || !ID_PATTERN.test(id)) throw data(null, { status: 404 });
  let entry: Awaited<ReturnType<ReturnType<typeof getData>['entry']>>;
  try {
    entry = await getData(request).entry(id);
  } catch (err) {
    if (err instanceof ApiBadRequest) throw data(null, { status: 404 });
    throw err;
  }
  if (!entry) throw data(null, { status: 404 });
  // Another case or an alias goes to the one canonical address.
  if (entry.key !== id) throw redirect(`/e/${encodeURIComponent(entry.key)}`, 301);
  // Signed in: the full view and the watch state come from account calls. The preview above stays the only
  // source of the meta tags and JSON-LD.
  let full: EntryFullView | null = null;
  let watching = false;
  let signedIn = false;
  const account = await getAccount(args);
  if (account) {
    try {
      const [f, list] = await bridge(() =>
        Promise.all([account.client.entryFull(entry.key), account.client.watchList()]),
      );
      full = f;
      watching = list.items.some((i) => i.entryKey === entry.key);
      signedIn = true;
    } catch (err) {
      // An expired token is just "signed out"; anything else (502) is an error page.
      if (!(err instanceof SignInRequired)) throw err;
    }
  }
  return { origin: siteOrigin(request), entry, signedIn, full, watching };
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Not found') }];
  const { entry, origin } = loaderData;
  return buildMeta({
    title: pageTitle(`${entry.key}: ${entry.title}`),
    description: entry.summary,
    path: `/e/${encodeURIComponent(entry.key)}`,
    origin,
  });
}

const TABS = [
  { id: 'evidence', label: 'Evidence' },
  { id: 'advisories', label: 'Advisories' },
  { id: 'changes', label: 'Changes' },
] as const;
type TabId = (typeof TABS)[number]['id'];

export default function Entry({ loaderData }: Route.ComponentProps) {
  const { entry, origin, signedIn, full, watching } = loaderData;
  const nonce = useNonce();
  const type = displayType(entry.kind, entry.key);
  const tabs = type === 'term' ? [] : TABS;
  const credits = entry.credits;
  const [search] = useSearchParams();
  const requested = search.get('tab');
  const tab: TabId | null = signedIn ? (TABS.find((t) => t.id === requested)?.id ?? null) : null;
  useGateOnce(entry.key, signedIn, type !== 'term');
  return (
    <div className="entry-layout">
      <article>
        <nav className="crumbs" aria-label="Breadcrumb">
          <Link to="/">Home</Link>
          <span aria-hidden="true">/</span>
          <Link to={`/search?type=${type}`}>{TYPE_PLURALS[type]}</Link>
          <span aria-hidden="true">/</span>
          <span>{entry.key}</span>
        </nav>
        <header className="entry-head">
          <div className="entry-ids">
            <TypeBadge type={type} />
            <span className="mono">{entry.key}</span>
            {entry.aliases.map((a) => (
              <Chip key={a}>{a}</Chip>
            ))}
          </div>
          <h1>{entry.title}</h1>
          <div className="chips">
            {entry.exploited ? <Chip tone="kev">Exploited in the wild</Chip> : null}
            {type === 'vuln' && !entry.exploited ? <Chip>Not on CISA KEV</Chip> : null}
            {entry.cvss !== undefined ? (
              <Chip>
                CVSS {entry.cvss.toFixed(1)}
                {entry.cvssVersion ? ` (v${entry.cvssVersion.replace(/^v/i, '')})` : ''}
              </Chip>
            ) : null}
          </div>
        </header>

        <TabBar label="Record sections">
          <li>
            <Link
              className="tab"
              to={`/e/${encodeURIComponent(entry.key)}`}
              aria-current={tab === null ? 'page' : undefined}
            >
              Overview
            </Link>
          </li>
          {tabs.map((t) => (
            <li key={t.id}>
              {signedIn ? (
                <Link
                  className="tab"
                  to={`/e/${encodeURIComponent(entry.key)}?tab=${t.id}`}
                  aria-current={tab === t.id ? 'page' : undefined}
                >
                  {t.label}
                </Link>
              ) : (
                <LockedTab entryKey={entry.key} tab={t.id} label={t.label} />
              )}
            </li>
          ))}
        </TabBar>

        {signedIn ? (
          <WatchButton entryKey={entry.key} watching={watching} />
        ) : (
          <LockedWatch entryKey={entry.key} />
        )}

        {tab === null ? (
          <section aria-labelledby="summary-title">
            <h2 id="summary-title" className="label">
              Summary
            </h2>
            <p>{entry.summary}</p>
          </section>
        ) : full === null ? (
          <p className="notice">The full record is not available for this entry yet.</p>
        ) : tab === 'evidence' ? (
          <EvidencePanel entry={full} />
        ) : tab === 'advisories' ? (
          <AdvisoriesPanel entry={full} />
        ) : (
          <ChangesPanel entry={full} />
        )}

        {tab === null && !signedIn && type !== 'term' ? <GateCard entryKey={entry.key} /> : null}
        <CreditList credits={credits} />
      </article>

      <aside className="panel glance" aria-labelledby="glance-title">
        <h2 id="glance-title">At a glance</h2>
        <dl>
          <div>
            <dt className="label">CVSS</dt>
            <dd>
              {entry.cvss === undefined ? (
                'Not scored'
              ) : (
                <span className="cvss">
                  <span className="cvss-number">{entry.cvss.toFixed(1)}</span>
                  <CvssMeter score={entry.cvss} />
                  {entry.cvssSource ? <span className="muted"> scored by {entry.cvssSource}</span> : null}
                </span>
              )}
            </dd>
          </div>
          <div>
            <dt className="label">CISA KEV</dt>
            <dd>{entry.kevAdded ? `Added ${formatDate(entry.kevAdded)}` : 'Not on the list'}</dd>
          </div>
          {entry.epss === undefined ? null : (
            <div>
              <dt className="label">EPSS</dt>
              <dd>{`${(entry.epss * 100).toFixed(entry.epss >= 0.1 ? 0 : 1)}%`}</dd>
            </div>
          )}
          {entry.published ? (
            <div>
              <dt className="label">Published</dt>
              <dd>{formatDate(entry.published)}</dd>
            </div>
          ) : null}
          {entry.modified ? (
            <div>
              <dt className="label">Modified</dt>
              <dd>{formatDate(entry.modified)}</dd>
            </div>
          ) : null}
          <div>
            <dt className="label">Coverage</dt>
            <dd>
              Built from {credits.length} {credits.length === 1 ? 'source' : 'sources'}
            </dd>
          </div>
        </dl>
      </aside>

      <JsonLd
        nonce={nonce}
        data={{
          '@context': 'https://schema.org',
          '@type': 'WebPage',
          name: `${entry.key}: ${entry.title}`,
          description: entry.summary,
          identifier: entry.key,
          isPartOf: { '@type': 'WebSite', name: SITE_NAME, url: origin },
          url: new URL(`/e/${encodeURIComponent(entry.key)}`, origin).toString(),
          ...(entry.published ? { datePublished: entry.published } : {}),
          ...(entry.modified ? { dateModified: entry.modified } : {}),
        }}
      />
    </div>
  );
}

/** Opens the sign-up modal once per entry visit (keyed on the entry), never on a re-render or revalidation. */
function useGateOnce(entryKey: string, signedIn: boolean, gated: boolean) {
  const { isLoaded, isSignedIn, available } = useAuthState();
  const open = useOpenSignUp();
  const opened = useRef<string | null>(null);
  useEffect(() => {
    if (!gated || signedIn || isSignedIn || !isLoaded || !available) return;
    if (opened.current === entryKey) return;
    opened.current = entryKey;
    open({ fallbackRedirectUrl: window.location.href });
  }, [gated, signedIn, isSignedIn, isLoaded, available, entryKey, open]);
}

function LockedTab({ entryKey, tab, label }: { entryKey: string; tab: TabId; label: string }) {
  const { available } = useAuthState();
  const open = useOpenSignUp();
  return (
    <button
      type="button"
      className="tab tab-locked"
      disabled={!available}
      onClick={() => {
        saveIntent({ action: 'tab', target: `${entryKey}#${tab}` });
        open({ fallbackRedirectUrl: window.location.href });
      }}
    >
      {label}
      <small aria-hidden="true">free account</small>
      <span className="visually-hidden"> (needs a free account)</span>
    </button>
  );
}

function WatchButton({ entryKey, watching }: { entryKey: string; watching: boolean }) {
  const { submit, fetcher, result } = useAccountFetcher();
  const pending = fetcher.formData?.get('intent');
  const isWatching = pending === 'watch' ? true : pending === 'unwatch' ? false : watching;
  return (
    <div className="watch-row">
      <button
        type="button"
        className={isWatching ? 'button' : 'button button-primary'}
        aria-pressed={isWatching}
        onClick={() => submit({ intent: isWatching ? 'unwatch' : 'watch', id: entryKey })}
      >
        {isWatching ? 'Watching' : 'Watch'}
      </button>
      <span className="muted" role="status">
        {result && !result.ok
          ? errorText(result.error)
          : result?.ok && result.intent === 'watch'
            ? `Watching ${entryKey}`
            : ''}
      </span>
    </div>
  );
}

function ExternalLink({ url, label }: { url?: string; label: string }) {
  return url ? (
    <a href={url} rel="noopener noreferrer nofollow">
      {label}
    </a>
  ) : null;
}

function EvidencePanel({ entry }: { entry: EntryFullView }) {
  const evidence = groupEvidence(entry);
  return (
    <section aria-labelledby="evidence-title">
      <h2 id="evidence-title" className="label">
        Evidence
      </h2>
      <p className="muted">Each kind of evidence is shown on its own. They are never added into one score.</p>
      {evidence.groups.length === 0 ? (
        <p>No exploitation, exploit-code or detection signals are recorded.</p>
      ) : null}
      {evidence.groups.map((g) => (
        <div className="evidence-group panel" key={g.id} data-group={g.id}>
          <h3>{g.title}</h3>
          <p className="muted">{g.note}</p>
          {g.kevAdded ? <p>Added to CISA KEV on {formatDate(g.kevAdded)}.</p> : null}
          {g.items.length > 0 ? (
            <ul>
              {g.items.map((i) => (
                <li key={`${i.source}:${i.ref}`}>
                  <span className="mono">{i.ref}</span> · {i.source} · first seen {formatDate(i.firstSeen)}{' '}
                  <ExternalLink url={i.url} label="Link" />
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ))}
      {evidence.prediction ? (
        <div className="evidence-group panel" data-group="prediction">
          <h3>Prediction</h3>
          <p className="muted">
            EPSS is a model’s probability of exploitation, not evidence that it happened.
          </p>
          <p>
            Probability of exploitation in the next 30 days:{' '}
            <strong>{`${(evidence.prediction.epss * 100).toFixed(evidence.prediction.epss >= 0.1 ? 0 : 1)}%`}</strong>
          </p>
        </div>
      ) : null}
    </section>
  );
}

function AdvisoriesPanel({ entry }: { entry: EntryFullView }) {
  return (
    <section aria-labelledby="advisories-title">
      <h2 id="advisories-title" className="label">
        Advisories
      </h2>
      {entry.cwe.length > 0 ? <p>Weakness: {entry.cwe.join(', ')}</p> : null}
      {entry.advisories.length === 0 ? <p>No advisories are shown for this entry.</p> : null}
      {entry.advisories.map((a) => (
        <div className="panel evidence-group" key={`${a.source}:${a.sourceId}`}>
          <h3>
            {a.source} <span className="mono">{a.sourceId}</span>
          </h3>
          {a.display === 'full' ? (
            <>
              <p className="muted">
                {a.status}
                {a.published ? ` · published ${formatDate(a.published)}` : ''}
              </p>
              {a.affected?.length ? (
                <ul>
                  {a.affected.map((f) => (
                    <li
                      key={`${f.ecosystem}:${f.name}:${f.introduced ?? ''}:${f.fixed ?? ''}:${f.range ?? ''}`}
                    >
                      {f.ecosystem} <span className="mono">{f.name}</span>
                      {f.introduced ? ` from ${f.introduced}` : ''}
                      {f.fixed ? `, fixed in ${f.fixed}` : ''}
                      {f.range ? ` (${f.range})` : ''}
                    </li>
                  ))}
                </ul>
              ) : null}
            </>
          ) : null}
          <p>
            <ExternalLink url={a.url} label="Read it at the source" />
          </p>
        </div>
      ))}
    </section>
  );
}

function ChangesPanel({ entry }: { entry: EntryFullView }) {
  const rows = [...entry.changes].sort((a, b) => b.at.localeCompare(a.at));
  return (
    <section aria-labelledby="changes-title">
      <h2 id="changes-title" className="label">
        Changes
      </h2>
      {rows.length === 0 ? <p>No changes are recorded yet.</p> : null}
      <ol className="changes">
        {rows.map((c) => (
          <li key={`${c.at}:${c.kind}:${c.new ?? ''}`}>
            <span className="mono">{formatDate(c.at)}</span> · {c.kind}
            {c.old ? `: ${c.old} →` : ':'} {c.new ?? ''}
            {c.source ? ` (${c.source})` : ''}
          </li>
        ))}
      </ol>
    </section>
  );
}

/** Signed out: remember the intent to watch, open the sign-up modal; the watch runs after sign-in. */
function LockedWatch({ entryKey }: { entryKey: string }) {
  const { available } = useAuthState();
  const open = useOpenSignUp();
  if (!available) return null;
  return (
    <div className="watch-row">
      <button
        type="button"
        className="button button-primary"
        onClick={() => {
          saveIntent({ action: 'watch', target: entryKey });
          open({ fallbackRedirectUrl: window.location.href });
        }}
      >
        Watch
      </button>
    </div>
  );
}
