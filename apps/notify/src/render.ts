import { PRODUCT_INTRO, PRODUCT_SHORT } from '@ti/core/brand';
import type { EmailKind } from '@ti/core/email';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import type { Change } from './collect';

export interface RenderItem {
  change: Change;
  /** Vuln title or key, company name or key. */
  title: string;
  company: boolean;
  /** Saved search label, or null for a watched entry or package. */
  group: string | null;
  /** Set for a package-watch alert. */
  pkg?: PackageInfo;
}

export interface PackageInfo {
  /** `ecosystem/name` from our `affected` row (already normalised). */
  label: string;
  /** `ecosystem/name` for the subject, from the user's own watch row; null when the name fails the check. */
  subjectLabel: string | null;
  /** Up to five distinct fixed versions for this package, ordered; empty means none yet. */
  fixed: string[];
  /** The fixed versions could not be read: the line says "fixed version: see MTI". */
  unknownFixed?: boolean;
  /** More fixed versions exist than are listed. */
  moreFixed?: boolean;
}

/** The `ecosystem/name` of a watch row for a subject, or null when the name could carry anything else. */
export function subjectPackage(ecosystem: string, name: string): string | null {
  const label = clean(`${ecosystem}/${name}`);
  return SHOWN_NAME.test(label) ? defang(label) : null;
}

export interface RenderInput {
  kind: EmailKind;
  items: RenderItem[];
  /** Queued updates this email covers but does not list: "and N more updates on your watchlist". */
  more?: number;
  appBase: string;
  unsubscribeUrl: string;
}

export interface Rendered {
  subject: string;
  text: string;
  html: string;
}

/** Replaces control and line-separator characters (incl. CR/LF) with a space, so a value stays on one line. */
export function clean(s: string): string {
  let out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    out += c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029 ? ' ' : ch;
  }
  // Format characters (bidi controls, zero-width characters, ...) are removed: they can make text read as something else.
  return out
    .replace(/\p{Cf}/gu, '')
    .replace(/ {2,}/g, ' ')
    .trim();
}

/** A package name or entry ID is shown only if it is made of these characters. */
const SHOWN_NAME = /^[A-Za-z0-9@/._:-]{1,100}$/;
/** A fixed version is shown only if it is made of these characters. */
const SHOWN_VERSION = /^[A-Za-z0-9.+~:_-]{1,40}$/;
export const UNSHOWN_NAME = 'a package (see your watchlist)';

/**
 * Writes every dot followed by a letter as `[.]` (`Go/verify-mti[.]com/reset[.]v2`), so a mail client does not
 * turn the value into a link. `always` does it for every dot (client hosts). `://` is written `[:]//`.
 */
export function defang(v: string, always = false): string {
  return v.replace(always ? /\./g : /\.(?=[A-Za-z])/g, '[.]').replace(/:\/\//g, '[:]//');
}

/** A package name or entry ID as it may be shown: checked, then defanged. */
export function shownName(v: string): string {
  const t = clean(v);
  return SHOWN_NAME.test(t) ? defang(t) : UNSHOWN_NAME;
}
const cut = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function pct(v: string | null): string {
  const n = Number(v);
  return v !== null && v !== '' && Number.isFinite(n) ? `${(n * 100).toFixed(1)}%` : (v ?? 'unknown');
}

/** "Package: PyPI/langchain. Fixed in 1.2.3" for a package alert; empty for anything else. */
export function packageLine(i: RenderItem): string {
  if (!i.pkg) return '';
  if (i.pkg.unknownFixed) return `Package: ${shownName(i.pkg.label)}. fixed version: see MTI`;
  const versions = i.pkg.fixed.map(clean).filter((v) => SHOWN_VERSION.test(v));
  const fixed =
    versions.length > 0
      ? `Fixed in ${versions.map((v) => defang(v)).join(', ')}${i.pkg.moreFixed ? ' and more' : ''}`
      : 'no fixed version yet';
  return `Package: ${shownName(i.pkg.label)}. ${fixed}`;
}

/** The change in words. */
export function describeChange(c: Change): string {
  switch (c.kind) {
    case 'newly_exploited':
      return `Exploited in the wild: added to CISA KEV${c.new ? ` on ${clean(c.new)}` : ''}`;
    case 'public_exploit':
      return 'Public exploit published';
    case 'epss_band':
      return `EPSS moved from ${pct(c.old)} to ${pct(c.new)}`;
    case 'fix_released':
      return 'Fix released';
    case 'cvss_change':
      return `CVSS changed from ${clean(c.old ?? 'unknown')} to ${clean(c.new ?? 'unknown')}`;
    case 'breach_notice':
      return 'New breach notice';
    case 'new_advisory':
      return 'New advisory';
    default:
      return 'Updated';
  }
}

function shortChange(c: Change): string {
  switch (c.kind) {
    case 'newly_exploited':
      return 'is exploited';
    case 'public_exploit':
      return 'has a public exploit';
    case 'epss_band':
      return 'EPSS moved';
    case 'fix_released':
      return 'has a fix';
    case 'cvss_change':
      return 'CVSS changed';
    case 'breach_notice':
      return 'has a new breach notice';
    case 'new_advisory':
      return 'has a new advisory';
    default:
      return 'was updated';
  }
}

export function itemTitle(i: RenderItem): string {
  if (i.pkg) return shownName(i.change.entity_key); // a package alert shows our key, not a source's title
  return cut(clean(i.title) || clean(i.change.entity_key), 140);
}

export function itemLink(i: RenderItem, appBase: string): string {
  const base = appBase.replace(/\/+$/, '');
  return i.company
    ? `${base}/search?type=breach&q=${encodeURIComponent(i.title)}`
    : `${base}/e/${encodeURIComponent(i.change.entity_key)}`;
}

/**
 * The subject of a one-item instant email. No text from any source: the entry ID (checked) or the package from
 * the user's own watch row, never a title.
 */
function singleSubject(i: RenderItem): string {
  if (i.pkg && i.change.kind === 'new_advisory')
    return `${PRODUCT_SHORT}: new advisory for ${i.pkg.subjectLabel ?? 'a watched package'}`;
  const key = clean(i.change.entity_key);
  const who =
    SHOWN_NAME.test(key) && !key.includes('/')
      ? defang(key)
      : i.pkg
        ? (i.pkg.subjectLabel ?? 'a watched package')
        : 'a watched entry';
  return `${PRODUCT_SHORT}: ${who} ${shortChange(i.change)}`;
}

export function subjectFor(kind: EmailKind, items: RenderItem[], more = 0): string {
  const n = items.length + more;
  let s: string;
  if (kind === 'instant')
    s = n === 1 && items[0] ? singleSubject(items[0]) : `${PRODUCT_SHORT}: ${n} updates on your watchlist`;
  else s = `${PRODUCT_SHORT} ${kind} digest: ${n} updates`;
  return cut(clean(s), 150);
}

function credits(items: RenderItem[]): string {
  const out = new Set<string>();
  for (const i of items) {
    const id = i.change.source;
    if (!id) continue;
    out.add(SOURCE_BY_ID.get(id)?.credit ?? `Source: ${clean(id)}`);
  }
  return [...out].join('; ');
}

function reasonFor(kind: EmailKind): string {
  return kind === 'instant'
    ? 'You are getting this because you turned on instant alerts for entries and packages you watch.'
    : `You are getting this ${kind} digest because you turned on alerts for entries or packages you watch or searches you saved.`;
}

interface Group {
  heading: string | null;
  items: RenderItem[];
}
/** Watched entries first, then saved-search matches grouped by label. */
function grouped(items: RenderItem[]): Group[] {
  const groups: Group[] = [];
  const watched = items.filter((i) => i.group === null);
  if (watched.length > 0) groups.push({ heading: null, items: watched });
  const byLabel = new Map<string, RenderItem[]>();
  for (const i of items) if (i.group !== null) byLabel.set(i.group, [...(byLabel.get(i.group) ?? []), i]);
  for (const [label, its] of byLabel)
    groups.push({ heading: `Matches for "${cut(clean(label), 100)}"`, items: its });
  return groups;
}

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";

export function renderEmail(input: RenderInput): Rendered {
  const { kind, items, appBase, unsubscribeUrl } = input;
  const more = Math.max(0, input.more ?? 0);
  const subject = subjectFor(kind, items, more);
  const groups = grouped(items);
  const reason = reasonFor(kind);
  const manage = `${appBase.replace(/\/+$/, '')}/account`;
  const credit = credits(items);

  const text: string[] = [subject, ''];
  for (const g of groups) {
    if (g.heading) text.push(g.heading, '');
    for (const i of g.items)
      text.push(
        `- ${itemTitle(i)}`,
        `  ${describeChange(i.change)}`,
        ...(i.pkg ? [`  ${packageLine(i)}`] : []),
        `  ${itemLink(i, appBase)}`,
        '',
      );
  }
  const watchlist = `${appBase.replace(/\/+$/, '')}/account`;
  if (more > 0) text.push(`and ${more} more updates on your watchlist: ${watchlist}`, '');
  text.push(
    reason,
    `Manage alerts: ${manage}`,
    `Unsubscribe: ${unsubscribeUrl}`,
    ...(credit ? [`Data: ${credit}`] : []),
    PRODUCT_INTRO,
  );

  const rows: string[] = [];
  for (const g of groups) {
    if (g.heading)
      rows.push(
        `<tr><td style="padding:16px 24px 4px;font:600 14px ${FONT};color:#121212">${escapeHtml(g.heading)}</td></tr>`,
      );
    for (const i of g.items)
      rows.push(
        `<tr><td style="padding:12px 24px;border-top:1px solid #e6e4de;font:14px/1.4 ${FONT};color:#121212">` +
          `<a href="${escapeHtml(itemLink(i, appBase))}" style="color:#121212;font-weight:600;text-decoration:none">${escapeHtml(itemTitle(i))}</a><br>` +
          `<span style="color:#ef7d45">${escapeHtml(describeChange(i.change))}</span>` +
          (i.pkg ? `<br><span style="color:#6b6a64">${escapeHtml(packageLine(i))}</span>` : '') +
          `</td></tr>`,
      );
  }
  if (more > 0)
    rows.push(
      `<tr><td style="padding:12px 24px;border-top:1px solid #e6e4de;font:14px/1.4 ${FONT};color:#121212">` +
        `<a href="${escapeHtml(watchlist)}" style="color:#121212">and ${more} more updates on your watchlist</a></td></tr>`,
    );
  const foot = (s: string) => `<div style="margin:0 0 6px">${s}</div>`;
  const html =
    `<!doctype html><html><body style="margin:0;padding:0;background:#fafaf8">` +
    `<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:100%;margin:0 auto;background:#fafaf8">` +
    `<tr><td style="padding:24px 24px 12px;font:600 18px ${FONT};color:#121212">${escapeHtml(subject)}</td></tr>` +
    `<tr><td><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e6e4de">${rows.join('')}</table></td></tr>` +
    `<tr><td style="padding:16px 24px 24px;font:12px/1.5 ${FONT};color:#6b6a64">` +
    foot(escapeHtml(reason)) +
    foot(
      `<a href="${escapeHtml(manage)}" style="color:#6b6a64">Manage alerts</a> · <a href="${escapeHtml(unsubscribeUrl)}" style="color:#6b6a64">Unsubscribe</a>`,
    ) +
    (credit ? foot(`Data: ${escapeHtml(credit)}`) : '') +
    foot(PRODUCT_INTRO) +
    `</td></tr></table></body></html>`;

  return { subject, text: text.join('\n'), html };
}

export interface NoticeEvent {
  at: string;
  action: string;
  target: string;
  clientHost: string | null;
}

const ACTION_TEXT: Record<string, string> = {
  add: 'Added to your watchlist',
  remove: 'Removed from your watchlist',
  alerts_on: 'Alerts turned on for',
  digest_on: 'Email digest turned on',
};

/** One change in words. Every value is plain text, cut to 100 characters, never a link. */
export function noticeLine(e: NoticeEvent): string {
  const what = ACTION_TEXT[e.action] ?? 'Changed';
  const target = e.target === 'settings' ? '' : `: ${shownName(e.target.replace(/^(pkg|entry):/, ''))}`;
  const app = e.clientHost ? ` · app (self-reported): ${defang(cut(clean(e.clientHost), 100), true)}` : '';
  return `${what}${target}${app} · ${defang(cut(clean(e.at), 100))}`;
}

export const NOTICE_SUBJECT = 'Your MTI watchlist was changed';

/** "Your MTI watchlist was changed": sent when an app changed the watchlist for the user, even with alerts off. */
export function renderWatchNotice(events: NoticeEvent[], appBase: string): Rendered {
  const link = `${appBase.replace(/\/+$/, '')}/account`;
  const lines = events.map(noticeLine);
  const intro = 'An app connected to your account through MCP changed your watchlist or alert settings:';
  const outro = 'If you did not expect this, review your watchlist and your connected apps now.';
  const text = [
    NOTICE_SUBJECT,
    '',
    intro,
    '',
    ...lines.map((l) => `- ${l}`),
    '',
    outro,
    `Watchlist: ${link}`,
    PRODUCT_INTRO,
  ];
  const html =
    `<!doctype html><html><body style="margin:0;padding:0;background:#fafaf8">` +
    `<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:100%;margin:0 auto;background:#fafaf8">` +
    `<tr><td style="padding:24px 24px 12px;font:600 18px ${FONT};color:#121212">${escapeHtml(NOTICE_SUBJECT)}</td></tr>` +
    `<tr><td style="padding:0 24px 12px;font:14px/1.5 ${FONT};color:#121212">${escapeHtml(intro)}</td></tr>` +
    lines
      .map(
        (l) =>
          `<tr><td style="padding:8px 24px;border-top:1px solid #e6e4de;font:14px/1.4 ${FONT};color:#121212">${escapeHtml(l)}</td></tr>`,
      )
      .join('') +
    `<tr><td style="padding:16px 24px 24px;font:12px/1.5 ${FONT};color:#6b6a64">${escapeHtml(outro)}<br>` +
    `<a href="${escapeHtml(link)}" style="color:#6b6a64">Your watchlist</a><br>${escapeHtml(PRODUCT_INTRO)}</td></tr></table></body></html>`;
  return { subject: NOTICE_SUBJECT, text: text.join('\n'), html };
}
