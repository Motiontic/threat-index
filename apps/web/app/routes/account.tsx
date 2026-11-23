import { MAX_DISPLAY_NAME_CHARS } from '@ti/core/account';
import { useEffect, useState } from 'react';
import { Link, redirect, useSearchParams } from 'react-router';
import { errorText, useAccountFetcher } from '../components/account-bits';
import { EmptyState } from '../components/ui';
import { SignInRequired } from '../data/api.server';
import { bridge, getAccount } from '../data/data.server';
import type { Me, SavedSearch, WatchItem } from '../data/types';
import { DELETE_PHRASE } from '../lib/account-phrase';
import { useSignOut } from '../lib/auth';
import { formatDate } from '../lib/format';
import { savedSearchHref } from '../lib/search-params';
import { buildMeta, pageTitle } from '../lib/seo';
import type { Route } from './+types/account';

const SIGN_IN = '/sign-in?redirect_url=%2Faccount';
const TABS = [
  { id: 'profile', label: 'Profile and alerts' },
  { id: 'watch', label: 'Watchlist' },
  { id: 'saved', label: 'Saved searches' },
  { id: 'delete', label: 'Delete account' },
] as const;
type TabId = (typeof TABS)[number]['id'];

export async function loader(args: Route.LoaderArgs) {
  const account = await getAccount(args);
  if (!account) throw redirect(SIGN_IN);
  try {
    const [me, watch, saved] = await bridge(() =>
      Promise.all([account.client.me(), account.client.watchList(), account.client.savedList()]),
    );
    return { origin: new URL(args.request.url).origin, me, watch, saved };
  } catch (err) {
    if (err instanceof SignInRequired) throw redirect(SIGN_IN);
    throw err;
  }
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Account') }];
  return buildMeta({
    title: pageTitle('Account'),
    description: 'Your profile, alerts, watchlist and saved searches.',
    path: '/account',
    origin: loaderData.origin,
    noindex: true,
  });
}

const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

export default function Account({ loaderData }: Route.ComponentProps) {
  const { me, watch, saved } = loaderData;
  const [params] = useSearchParams();
  const tab: TabId = TABS.find((t) => t.id === params.get('tab'))?.id ?? 'profile';
  return (
    <div>
      <div className="page-head">
        <h1>Account</h1>
        <span className="muted">{me.email}</span>
      </div>
      <ul className="tabs" aria-label="Account sections">
        {TABS.map((t) => (
          <li key={t.id}>
            <Link
              className="tab"
              to={t.id === 'profile' ? '/account' : `/account?tab=${t.id}`}
              aria-current={tab === t.id ? 'page' : undefined}
            >
              {t.label}
            </Link>
          </li>
        ))}
      </ul>
      {tab === 'profile' ? <ProfileTab me={me} /> : null}
      {tab === 'watch' ? <WatchTab items={watch.items} limit={watch.limit} /> : null}
      {tab === 'saved' ? <SavedTab items={saved.items} limit={saved.limit} /> : null}
      {tab === 'delete' ? <DeleteTab /> : null}
    </div>
  );
}

function ProfileTab({ me }: { me: Me }) {
  const { fetcher, submit, result } = useAccountFetcher();
  const [digest, setDigest] = useState(me.alerts.digest);
  return (
    <form
      className="panel account-form"
      onSubmit={(e) => {
        e.preventDefault();
        submit(e.currentTarget);
      }}
    >
      <input type="hidden" name="intent" value="profile" />
      <div>
        <label className="label" htmlFor="displayName">
          Display name
        </label>
        <input
          id="displayName"
          className="input"
          name="displayName"
          defaultValue={me.displayName ?? ''}
          maxLength={MAX_DISPLAY_NAME_CHARS}
          autoComplete="nickname"
        />
      </div>
      <label className="check">
        <input type="checkbox" name="instant" defaultChecked={me.alerts.instant} />
        Instant alerts when a watched record changes
      </label>
      <div>
        <label className="label" htmlFor="digest">
          Email digest
        </label>
        <select
          id="digest"
          className="input"
          name="digest"
          value={digest}
          onChange={(e) => setDigest(e.target.value as typeof digest)}
        >
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="off">Off</option>
        </select>
      </div>
      <div hidden={digest !== 'weekly'}>
        <label className="label" htmlFor="digestWeekday">
          Weekly digest day (UTC)
        </label>
        <select
          id="digestWeekday"
          className="input"
          name="digestWeekday"
          defaultValue={String(me.alerts.digestWeekday)}
        >
          {DAYS.map((d, i) => (
            <option key={d} value={String(i)}>
              {d}
            </option>
          ))}
        </select>
      </div>
      <div className="filter-actions">
        <button type="submit" className="button button-primary" disabled={fetcher.state !== 'idle'}>
          Save
        </button>
        <span role="status" className="muted">
          {result ? (result.ok ? 'Saved' : errorText(result.error)) : ''}
        </span>
      </div>
    </form>
  );
}

function WatchTab({ items, limit }: { items: WatchItem[]; limit: number }) {
  return (
    <section aria-labelledby="watch-title">
      <h2 id="watch-title" className="label">
        Watchlist · {items.length} of {limit}
      </h2>
      {items.length === 0 ? (
        <EmptyState title="You are not watching anything yet">
          <p>
            Open a record and press <strong>Watch</strong> to get alerts when it changes.
          </p>
        </EmptyState>
      ) : (
        <ul className="rows">
          {items.map((i) => (
            <WatchRow key={i.entryKey} item={i} />
          ))}
        </ul>
      )}
    </section>
  );
}

function WatchRow({ item }: { item: WatchItem }) {
  const { fetcher, submit, result } = useAccountFetcher();
  const pendingOn = fetcher.formData?.get('alertsOn');
  const alertsOn = pendingOn === undefined || pendingOn === null ? item.alertsOn : pendingOn === 'true';
  const removing = fetcher.formData?.get('intent') === 'unwatch';
  if (removing) return null;
  return (
    <li className="row">
      <div>
        <Link to={`/e/${encodeURIComponent(item.entryKey)}`}>{item.title}</Link>
        <span className="mono muted"> {item.entryKey}</span>
        <span className="muted"> · watching since {formatDate(item.createdAt)}</span>
        {result && !result.ok ? <span className="muted"> · {errorText(result.error)}</span> : null}
      </div>
      <div className="row-actions">
        <label className="check">
          <input
            type="checkbox"
            checked={alertsOn}
            onChange={(e) =>
              submit({ intent: 'watch-alerts', id: item.entryKey, alertsOn: String(e.target.checked) })
            }
          />
          Alerts
        </label>
        <button
          type="button"
          className="button"
          onClick={() => submit({ intent: 'unwatch', id: item.entryKey })}
        >
          Remove
        </button>
      </div>
    </li>
  );
}

function filtersText(s: SavedSearch): string {
  const p = s.params;
  const parts = [
    ...(p.type ?? []).map((t) => `type: ${t}`),
    ...(p.sig ?? []).map((t) => `signal: ${t}`),
    ...(p.sev ?? []).map((t) => `severity: ${t}`),
    ...(p.year ?? []).map((t) => `year: ${t}`),
    ...(p.sort ? [`sort: ${p.sort}`] : []),
  ];
  return parts.join(' · ');
}

function SavedTab({ items, limit }: { items: SavedSearch[]; limit: number }) {
  return (
    <section aria-labelledby="saved-title">
      <h2 id="saved-title" className="label">
        Saved searches · {items.length} of {limit}
      </h2>
      {items.length === 0 ? (
        <EmptyState title="No saved searches yet">
          <p>
            Run a <Link to="/search?type=vuln">search</Link> and press <strong>Save search</strong>.
          </p>
        </EmptyState>
      ) : (
        <ul className="rows">
          {items.map((s) => (
            <SavedRow key={s.id} item={s} />
          ))}
        </ul>
      )}
    </section>
  );
}

function SavedRow({ item }: { item: SavedSearch }) {
  const { fetcher, submit } = useAccountFetcher();
  if (fetcher.formData?.get('intent') === 'delete-search') return null;
  const filters = filtersText(item);
  return (
    <li className="row">
      <div>
        <strong>{item.name}</strong>
        <div className="muted">
          {item.query ? <span className="mono">“{item.query}”</span> : 'No query'}
          {filters ? ` · ${filters}` : ''}
        </div>
        <div className="muted">
          Alerts {item.alertsOn ? 'on' : 'off'}. Changing alerts on a saved search is coming soon.
        </div>
      </div>
      <div className="row-actions">
        <Link className="button" to={savedSearchHref(item)}>
          Run
        </Link>
        <button
          type="button"
          className="button"
          onClick={() => submit({ intent: 'delete-search', id: item.id })}
        >
          Delete
        </button>
      </div>
    </li>
  );
}

function DeleteTab() {
  const { fetcher, submit, result } = useAccountFetcher();
  const signOut = useSignOut();
  const [typed, setTyped] = useState('');
  const done = result?.ok === true && result.intent === 'delete-account';
  useEffect(() => {
    if (done) void signOut('/?deleted=1');
  }, [done, signOut]);
  return (
    <section className="panel account-form" aria-labelledby="delete-title">
      <h2 id="delete-title">Delete your account</h2>
      <p>
        This removes your profile, your watchlist, your saved searches and your sign-in. It cannot be undone.
        Public records are not affected.
      </p>
      <label className="label" htmlFor="confirm">
        Type <span className="mono">{DELETE_PHRASE}</span> to confirm
      </label>
      <input
        id="confirm"
        className="input"
        value={typed}
        onChange={(e) => setTyped(e.target.value)}
        autoComplete="off"
      />
      <div className="filter-actions">
        <button
          type="button"
          className="button button-danger"
          disabled={typed !== DELETE_PHRASE || fetcher.state !== 'idle' || done}
          onClick={() => submit({ intent: 'delete-account', confirm: typed })}
        >
          Delete my account
        </button>
        <span role="status" className="muted">
          {result && !result.ok ? errorText(result.error) : done ? 'Account deleted. Signing out…' : ''}
        </span>
      </div>
    </section>
  );
}
