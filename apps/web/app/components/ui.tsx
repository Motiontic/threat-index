import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { displayType } from '../data/display';
import type { Credit, EntryType, SearchHit } from '../data/types';
import { formatDate, TYPE_LABELS } from '../lib/format';
import { OpenSignUpButton } from './account-bits';

export function TypeBadge({ type }: { type: EntryType }) {
  return <span className={`badge badge-${type}`}>{TYPE_LABELS[type]}</span>;
}

export function Chip({ children, tone }: { children: ReactNode; tone?: 'kev' | 'ok' | 'warn' | 'bad' }) {
  return <span className={tone ? `chip chip-${tone}` : 'chip'}>{children}</span>;
}

/** The facts a hit or a preview carries: KEV status, CVSS and the published date. */
export interface Facts {
  key: string;
  kind?: string;
  exploited: boolean;
  cvss?: number;
  published?: string;
}

export function previewChips(facts: Facts): ReactNode[] {
  const chips: ReactNode[] = [];
  if (displayType(facts.kind, facts.key) === 'vuln') {
    chips.push(
      facts.exploited ? (
        <Chip key="kev" tone="kev">
          Exploited in the wild
        </Chip>
      ) : (
        <Chip key="kev">Not on CISA KEV</Chip>
      ),
    );
  }
  if (facts.cvss !== undefined) chips.push(<Chip key="cvss">CVSS {facts.cvss.toFixed(1)}</Chip>);
  if (facts.published) chips.push(<Chip key="date">{formatDate(facts.published)}</Chip>);
  return chips;
}

export function ResultCard({ hit }: { hit: SearchHit & { kind?: string } }) {
  return (
    <article className="result-card">
      <div className="result-head">
        <TypeBadge type={displayType(hit.kind, hit.key)} />
        <span className="mono muted">{hit.key}</span>
      </div>
      <h2>
        <Link to={`/e/${encodeURIComponent(hit.key)}`}>{hit.title}</Link>
      </h2>
      <p>{hit.summary}</p>
      <div className="chips">{previewChips(hit)}</div>
    </article>
  );
}

export function CompactRow({ item, note }: { item: { key: string; title: string }; note?: string }) {
  return (
    <li className="row">
      <span className="mono muted">{item.key}</span>
      <span className="row-main">
        <Link to={`/e/${encodeURIComponent(item.key)}`}>{item.title}</Link>
      </span>
      {note ? <span className="muted">{note}</span> : null}
    </li>
  );
}

export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

export function Tile({ to, label, kev }: { to: string; label: string; kev?: boolean }) {
  return (
    <Link to={to} className={kev ? 'tile tile-kev' : 'tile'}>
      <span className="tile-label">{label}</span>
    </Link>
  );
}

/** A wide table scrolls inside its own wrapper, never the page. */
export function Table({ caption, head, children }: { caption: string; head: string[]; children: ReactNode }) {
  return (
    // biome-ignore lint/a11y/useSemanticElements: a scroll container, not a section
    // biome-ignore lint/a11y/noNoninteractiveTabindex: scrollable region must be focusable
    <div className="table-wrap" role="region" aria-label={caption} tabIndex={0}>
      <table className="table">
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            {head.map((h) => (
              <th key={h} scope="col">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function LetterBar({ current }: { current: string | null }) {
  const letters = [...'abcdefghijklmnopqrstuvwxyz', '0'];
  return (
    <nav className="letter-bar" aria-label="Index letters">
      {letters.map((l) => (
        <Link
          key={l}
          to={`/index/${l}`}
          className="letter"
          aria-current={current === l ? 'page' : undefined}
          aria-label={l === '0' ? 'Digits and symbols' : `Letter ${l.toUpperCase()}`}
        >
          {l === '0' ? '0–9' : l}
        </Link>
      ))}
    </nav>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

/** A credit's name links out only when its URL parses as https. */
export function safeHttpsUrl(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' ? u.toString() : null;
  } catch {
    return null;
  }
}

export function CreditList({ credits }: { credits: Credit[] }) {
  return (
    <section className="credits" aria-labelledby="credits-title">
      <h2 id="credits-title" className="label">
        Sources and credits
      </h2>
      <ul>
        {credits.map((c) => {
          const href = safeHttpsUrl(c.url);
          return (
            <li key={`${c.sourceId}-${c.text}`}>
              {href ? (
                <a href={href} rel="noopener noreferrer">
                  {c.name}
                </a>
              ) : (
                c.name
              )}
              {c.text ? <span className="muted"> {c.text}</span> : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

const PLACEHOLDER = [
  'Affected products, fixed versions and workarounds are listed here once you have a free account.',
  'The timeline shows when the flaw was reported, fixed and first seen in attacks, with the sources for each date.',
  'Related records link out to weaknesses, techniques and other entries that share this one’s identifiers.',
  'Scores, signals and references from every source that covers this entry appear in the full record.',
];

export function GateCard({ entryKey }: { entryKey: string }) {
  return (
    <div className="gate-wrap">
      <div className="gate-blur" aria-hidden="true">
        {PLACEHOLDER.map((p) => (
          <p key={p}>{p}</p>
        ))}
      </div>
      <section className="gate-card" aria-labelledby="gate-title" data-entry={entryKey}>
        <h2 id="gate-title">See the full record, free</h2>
        <ul>
          <li>Every source, score and reference in one place</li>
          <li>Timeline and related records</li>
          <li>Watch an entry and get an alert when it changes</li>
        </ul>
        <div className="gate-actions">
          <OpenSignUpButton primary>Sign up free</OpenSignUpButton>
          <OpenSignUpButton mode="in">Log in</OpenSignUpButton>
        </div>
      </section>
    </div>
  );
}

/** CVSS 0–10 as a bar. Red from 9.0. The number is also written out, so colour is never the only cue. */
export function CvssMeter({ score }: { score: number }) {
  const width = Math.round((Math.max(0, Math.min(10, score)) / 10) * 120);
  return (
    <svg
      width="120"
      height="8"
      viewBox="0 0 120 8"
      role="img"
      aria-label={`CVSS ${score.toFixed(1)} out of 10`}
    >
      <rect className="meter-track" width="120" height="8" rx="4" />
      <rect className={score >= 9 ? 'meter-fill-bad' : 'meter-fill'} width={width} height="8" rx="4" />
    </svg>
  );
}
