/** Pure formatting of the watchdog report and its raw email. No bindings, so Node tests cover it. */

export type FindingKind = 'late' | 'drop' | 'unknown-fields' | 'budget' | 'failed-runs' | 'jobs';

export interface Finding {
  kind: FindingKind;
  /** A source id, a database or a job id. */
  subject: string;
  detail: string;
}

export const MAX_FINDINGS_IN_REPORT = 200;
const MAX_LINE = 998;
// Keep every line well inside the limit, in characters.
const SAFE_LINE = 900;

const TITLES: Record<FindingKind, string> = {
  late: 'Late sources',
  drop: 'Records found dropped',
  'unknown-fields': 'Unknown fields',
  budget: 'Budget',
  'failed-runs': 'Failed runs',
  jobs: 'E2B jobs',
};
const ORDER: FindingKind[] = ['late', 'failed-runs', 'jobs', 'drop', 'unknown-fields', 'budget'];

/** Printable ASCII on one line: the message goes out as plain text without a transfer encoding. */
function clean(s: string): string {
  const flat = s.replace(/[\r\n\t]+/g, ' ').replace(/[^\x20-\x7e]/g, '?');
  return flat.length > SAFE_LINE ? `${flat.slice(0, SAFE_LINE - 3)}...` : flat;
}

export function formatReport(findings: readonly Finding[], now: Date): { subject: string; text: string } {
  const day = now.toISOString().slice(0, 10);
  const subject = `Threat Index watchdog ${day}: ${findings.length === 0 ? 'all clear' : `${findings.length} issues`}`;
  if (findings.length === 0) return { subject, text: 'All clear: nothing to report in the last 24 hours.\n' };

  const lines: string[] = [`${findings.length} issues in the last 24 hours.`, ''];
  let room = MAX_FINDINGS_IN_REPORT;
  for (const kind of ORDER) {
    const group = findings.filter((f) => f.kind === kind);
    if (group.length === 0) continue;
    // The heading counts every finding of the kind; the list is cut to what is left of the 200.
    lines.push(`${TITLES[kind]} (${group.length})`);
    for (const f of group.slice(0, room)) lines.push(clean(`- ${f.subject}: ${f.detail}`));
    room = Math.max(0, room - group.length);
    lines.push('');
  }
  const omitted = findings.length - MAX_FINDINGS_IN_REPORT;
  if (omitted > 0) lines.push(`...and ${omitted} more`);
  return { subject, text: `${lines.join('\n')}\n` };
}

function header(name: string, value: string): string {
  if (/[\r\n]/.test(value)) throw new Error(`header ${name} has a line break`);
  return `${name}: ${value}`;
}

/** An RFC 5322 plain-text message with CRLF line ends. Throws if a header value has CR or LF. */
export function buildRawEmail(m: {
  from: string;
  to: string;
  subject: string;
  text: string;
  date: Date;
  messageId: string;
}): string {
  const head = [
    header('From', m.from),
    header('To', m.to),
    header('Subject', m.subject),
    header('Date', m.date.toUTCString()),
    header('Message-ID', m.messageId),
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
  ];
  const body: string[] = [];
  for (const line of m.text.replace(/\r\n?/g, '\n').split('\n')) {
    if (line.length <= MAX_LINE) body.push(line);
    else for (let i = 0; i < line.length; i += MAX_LINE) body.push(line.slice(i, i + MAX_LINE));
  }
  while (body.length > 1 && body[body.length - 1] === '') body.pop();
  return `${head.join('\r\n')}\r\n\r\n${body.join('\r\n')}\r\n`;
}
