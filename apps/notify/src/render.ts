import type { EmailKind } from '@ti/core/email';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import type { Change } from './collect';

export interface RenderItem {
  change: Change;
  /** Vuln title or key, company name or key. */
  title: string;
  company: boolean;
  /** Saved search label, or null for a watched entry. */
  group: string | null;
}

export interface RenderInput {
  kind: EmailKind;
  items: RenderItem[];
  appBase: string;
  unsubscribeUrl: string;
}

export interface Rendered {
  subject: string;
  text: string;
  html: string;
}

/** Replaces control and line-separator characters (incl. CR/LF) with a space, so a value stays on one line. */
function clean(s: string): string {
  let out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    out += c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029 ? ' ' : ch;
  }
  return out.replace(/ {2,}/g, ' ').trim();
}
const cut = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function pct(v: string | null): string {
  const n = Number(v);
  return v !== null && v !== '' && Number.isFinite(n) ? `${(n * 100).toFixed(1)}%` : (v ?? 'unknown');
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
    default:
      return 'Updated';
  }
}

function shortChange(c: Change): string {
  switch (c.kind) {
    case 'newly_exploited':
      return 'exploited in the wild';
    case 'public_exploit':
      return 'has a public exploit';
    case 'epss_band':
      return 'EPSS moved';
    case 'fix_released':
      return 'fix released';
    case 'cvss_change':
      return 'CVSS changed';
    case 'breach_notice':
      return 'new breach notice';
    default:
      return 'updated';
  }
}

export function itemTitle(i: RenderItem): string {
  return cut(clean(i.title) || clean(i.change.entity_key), 140);
}

export function itemLink(i: RenderItem, appBase: string): string {
  const base = appBase.replace(/\/+$/, '');
  return i.company
    ? `${base}/search?type=breach&q=${encodeURIComponent(i.title)}`
    : `${base}/e/${encodeURIComponent(i.change.entity_key)}`;
}

export function subjectFor(kind: EmailKind, items: RenderItem[]): string {
  const n = items.length;
  let s: string;
  if (kind === 'instant')
    s =
      n === 1 && items[0]
        ? `Threat Index: ${itemTitle(items[0])} ${shortChange(items[0].change)}`
        : `Threat Index: ${n} updates on your watchlist`;
  else s = `Threat Index ${kind} digest: ${n} updates`;
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
    ? 'You are getting this because you turned on instant alerts for entries you watch.'
    : `You are getting this ${kind} digest because you turned on alerts for entries you watch or searches you saved.`;
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
  const subject = subjectFor(kind, items);
  const groups = grouped(items);
  const reason = reasonFor(kind);
  const manage = `${appBase.replace(/\/+$/, '')}/account`;
  const credit = credits(items);

  const text: string[] = [subject, ''];
  for (const g of groups) {
    if (g.heading) text.push(g.heading, '');
    for (const i of g.items)
      text.push(`- ${itemTitle(i)}`, `  ${describeChange(i.change)}`, `  ${itemLink(i, appBase)}`, '');
  }
  text.push(
    reason,
    `Manage alerts: ${manage}`,
    `Unsubscribe: ${unsubscribeUrl}`,
    ...(credit ? [`Data: ${credit}`] : []),
    'Threat Index by Motiontic',
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
          `<span style="color:#ef7d45">${escapeHtml(describeChange(i.change))}</span></td></tr>`,
      );
  }
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
    foot('Threat Index by Motiontic') +
    `</td></tr></table></body></html>`;

  return { subject, text: text.join('\n'), html };
}
