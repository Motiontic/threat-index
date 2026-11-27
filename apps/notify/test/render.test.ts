import { describe, expect, it } from 'vitest';
import type { Change } from '../src/collect';
import {
  clean,
  defang,
  describeChange,
  itemLink,
  noticeLine,
  type RenderItem,
  renderEmail,
  shownName,
  subjectFor,
} from '../src/render';

const ch = (kind: string, o: Partial<Change> = {}): Change => ({
  id: 'c1',
  entity_key: 'CVE-2026-0001',
  kind,
  old: null,
  new: null,
  at: '2026-11-23T01:00:00Z',
  source: 'osv',
  ...o,
});
const item = (o: Partial<RenderItem> & { change?: Change } = {}): RenderItem => ({
  change: ch('newly_exploited', { new: '2026-11-20' }),
  title: 'Acme Gateway RCE',
  company: false,
  group: null,
  ...o,
});
const base = { appBase: 'https://app.example', unsubscribeUrl: 'https://api.example/unsubscribe?t=tok' };

describe('describeChange', () => {
  it('words each kind', () => {
    expect(describeChange(ch('newly_exploited', { new: '2026-11-20' }))).toBe(
      'Exploited in the wild: added to CISA KEV on 2026-11-20',
    );
    expect(describeChange(ch('public_exploit'))).toBe('Public exploit published');
    expect(describeChange(ch('epss_band', { old: '0.012', new: '0.5' }))).toBe(
      'EPSS moved from 1.2% to 50.0%',
    );
    expect(describeChange(ch('fix_released'))).toBe('Fix released');
    expect(describeChange(ch('cvss_change', { old: '7.5', new: '9.8' }))).toBe(
      'CVSS changed from 7.5 to 9.8',
    );
    expect(describeChange(ch('breach_notice'))).toBe('New breach notice');
    expect(describeChange(ch('new_advisory'))).toBe('New advisory');
  });
});

describe('subjects', () => {
  it('starts every subject with the short name', () => {
    for (const kind of ['instant', 'daily', 'weekly'] as const)
      expect(subjectFor(kind, [item()]).startsWith('MTI')).toBe(true);
  });

  it('one item, many items, digests', () => {
    expect(subjectFor('instant', [item()])).toBe('MTI: CVE-2026-0001 is exploited');
    expect(subjectFor('instant', [item(), item()])).toBe('MTI: 2 updates on your watchlist');
    expect(subjectFor('daily', [item(), item()])).toBe('MTI daily digest: 2 updates');
    expect(subjectFor('weekly', [item()])).toBe('MTI weekly digest: 1 updates');
  });
  it('is one line of at most 150 characters', () => {
    const s = subjectFor('instant', [item({ title: `${'x'.repeat(300)}\r\nBcc: evil@example.com` })]);
    expect(s.length).toBeLessThanOrEqual(150);
    expect(s).not.toMatch(/[\r\n]/);
  });
});

describe('renderEmail', () => {
  it('escapes database values and encodes URLs', () => {
    const r = renderEmail({
      ...base,
      kind: 'instant',
      items: [
        item({
          title: '<script>alert(1)</script> & "q"',
          change: ch('newly_exploited', { entity_key: 'a b/c?d', new: '<b>' }),
        }),
      ],
    });
    expect(r.html).not.toContain('<script>');
    expect(r.html).not.toContain('<b>');
    expect(r.html).toContain('&#60;script&#62;');
    expect(r.html).toContain('https://app.example/e/a%20b%2Fc%3Fd');
    expect(r.html).not.toMatch(/<img|<script|<link|<style|src=/);
  });
  it('links companies to the breach search', () => {
    const i = item({
      company: true,
      title: 'Acme & Sons',
      change: ch('breach_notice', { entity_key: 'acme' }),
    });
    expect(itemLink(i, 'https://app.example/')).toBe(
      'https://app.example/search?type=breach&q=Acme%20%26%20Sons',
    );
  });
  it('groups saved-search matches under their label, after watched entries', () => {
    const r = renderEmail({
      ...base,
      kind: 'daily',
      items: [item({ group: 'My "kev" search', title: 'S1' }), item({ title: 'W1' })],
    });
    expect(r.text.indexOf('W1')).toBeLessThan(r.text.indexOf('S1'));
    expect(r.text).toContain('Matches for "My "kev" search"');
    expect(r.html).toContain('Matches for &#34;My &#34;kev&#34; search&#34;');
  });
  it('has the footer, unsubscribe link, deduped credits and the same content in text and HTML', () => {
    const r = renderEmail({
      ...base,
      kind: 'instant',
      items: [
        item(),
        item({ change: ch('public_exploit', { source: 'nope' }) }),
        item({ change: ch('fix_released', { source: 'osv' }) }),
      ],
    });
    for (const part of [r.text, r.html]) {
      expect(part).toContain('https://api.example/unsubscribe?t=tok');
      expect(part).toContain('MTI, the Motiontic Threat Index');
      expect(part).toContain('Source: nope');
      expect(part).toContain('https://app.example/account');
    }
    expect(r.text.match(/Data: (.*)/)?.[1]?.split('; ').length).toBe(2);
    expect(r.html).toContain('width="600"');
    expect(r.html).toContain('#ef7d45');
  });
});

describe('text that can look like something else', () => {
  it('clean strips format characters: bidi controls and zero-width', () => {
    expect(clean('a\u202eb\u200bc\u2066d\ufeffe')).toBe('abcde');
  });
  it('defang writes every dot followed by a letter as [.]; hosts every dot', () => {
    expect(defang('verify-mti.com')).toBe('verify-mti[.]com');
    expect(defang('1.2.3')).toBe('1.2.3');
    expect(defang('1.2.3rc')).toBe('1.2.3rc');
    expect(defang('left-pad.js')).toBe('left-pad[.]js');
    expect(defang('localhost', true)).toBe('localhost');
    expect(defang('agent.example.test', true)).toBe('agent[.]example[.]test');
    expect(defang('a.b1', true)).toBe('a[.]b1');
    expect(defang('http://10.0.0.1/x')).toBe('http[:]//10.0.0.1/x');
    expect(defang('a://b.c', true)).toBe('a[:]//b[.]c');
    expect(defang('Go/verify-mti.com/reset.v2')).toBe('Go/verify-mti[.]com/reset[.]v2');
    expect(defang('mti.com.evil.io')).toBe('mti[.]com[.]evil[.]io');
  });
  it('shownName shows only the allowed characters, else a fixed phrase', () => {
    expect(shownName('PyPI/langchain')).toBe('PyPI/langchain');
    expect(shownName('a\u202eb')).toBe('ab'); // format characters are removed first
    expect(shownName('npm/verify-mti.com')).toBe('npm/verify-mti[.]com');
    for (const bad of ['has space', '<b>x</b>', 'x'.repeat(101), '', 'click here: evil'])
      expect(shownName(bad)).toBe('a package (see your watchlist)');
  });
  it('a package alert leaves out a fixed version that is not a version and defangs the name', () => {
    const pkg = {
      label: 'npm/verify-mti.com',
      subjectLabel: null,
      fixed: ['1.2.3', 'Visit evil.example now', '2.0.0'],
    };
    const r = renderEmail({
      ...base,
      kind: 'daily',
      items: [item({ pkg, change: ch('new_advisory', { new: 'osv:X' }) })],
    });
    expect(r.text).toContain('Package: npm/verify-mti[.]com. Fixed in 1.2.3, 2.0.0');
    expect(r.text).not.toContain('evil');
  });
  it('a notice shows an odd target or host safely', () => {
    const l = noticeLine({
      at: '2026-11-23T08:00:00.000Z',
      action: 'add',
      target: 'pkg:npm/<x>',
      clientHost: 'evil.example.com',
    });
    expect(l).toContain('a package (see your watchlist)');
    expect(l).toContain('app (self-reported): evil[.]example[.]com');
  });
  it('"and N more updates on your watchlist" ends the email and counts into the subject', () => {
    const r = renderEmail({
      ...base,
      kind: 'instant',
      more: 7,
      items: [item()],
    });
    expect(r.subject).toBe('MTI: 8 updates on your watchlist');
    expect(r.text).toContain('and 7 more updates on your watchlist: https://app.example/account');
    expect(r.html).toContain('and 7 more updates on your watchlist');
  });
});
