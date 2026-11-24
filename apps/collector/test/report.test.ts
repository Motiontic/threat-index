import { describe, expect, it } from 'vitest';
import { buildRawEmail, type Finding, formatReport } from '../src/report';

const NOW = new Date('2026-11-23T14:45:00Z');
const f = (i: number): Finding => ({ kind: 'late', subject: `s${i}`, detail: 'never run' });

describe('formatReport', () => {
  it('all clear', () => {
    expect(formatReport([], NOW).subject).toBe('MTI watchdog 2026-11-23: all clear');
  });
  it('counts issues and groups them', () => {
    const r = formatReport([f(1), { kind: 'budget', subject: 'D1', detail: '1300000' }], NOW);
    expect(r.subject).toBe('MTI watchdog 2026-11-23: 2 issues');
    expect(r.text).toContain('Late sources (1)');
    expect(r.text).toContain('- s1: never run');
  });
  it('shows at most 200 findings, then how many more', () => {
    const r = formatReport(
      Array.from({ length: 230 }, (_, i) => f(i)),
      NOW,
    );
    expect(r.text.match(/^- s\d+:/gm)).toHaveLength(200);
    expect(r.text).toContain('...and 30 more');
    expect(r.text).toContain('Late sources (230)');
    expect([...r.text].every((c) => c.charCodeAt(0) < 128)).toBe(true);
  });
  it('keeps every line short and ASCII, one finding per line', () => {
    const r = formatReport(
      [{ kind: 'failed-runs', subject: 'osv', detail: `${'é'.repeat(3000)}\nsecond` }],
      NOW,
    );
    for (const line of r.text.split('\n')) expect(line.length).toBeLessThanOrEqual(998);
    expect(r.text).not.toContain('é');
  });
});

describe('buildRawEmail', () => {
  const base = {
    from: 'w@example.org',
    to: 'ops@example.com',
    subject: 'S',
    text: 'a\nb\n',
    date: NOW,
    messageId: '<id@example.org>',
  };
  it('has the required headers and CRLF line ends', () => {
    const raw = buildRawEmail(base);
    const [head, body] = raw.split('\r\n\r\n');
    expect(head?.split('\r\n')).toEqual([
      'From: w@example.org',
      'To: ops@example.com',
      'Subject: S',
      'Date: Mon, 23 Nov 2026 14:45:00 GMT',
      'Message-ID: <id@example.org>',
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
    ]);
    expect(body).toBe('a\r\nb\r\n');
    expect(raw.replace(/\r\n/g, '')).not.toMatch(/[\r\n]/);
  });
  it('wraps lines longer than 998 characters', () => {
    const raw = buildRawEmail({ ...base, text: 'x'.repeat(2500) });
    for (const line of raw.split('\r\n')) expect(line.length).toBeLessThanOrEqual(998);
  });
  it('throws on a header value with CR or LF', () => {
    for (const k of ['from', 'to', 'subject', 'messageId'] as const) {
      expect(() => buildRawEmail({ ...base, [k]: 'a\r\nBcc: x@y.z' })).toThrow();
      expect(() => buildRawEmail({ ...base, [k]: 'a\nb' })).toThrow();
    }
  });
});
