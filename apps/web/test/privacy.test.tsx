import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { renderToString } from 'react-dom/server';
import { StaticRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import { PrivacyPage as Privacy } from '../app/components/privacy-page';
import { Footer } from '../app/components/shell';
import { ownerPlaceholders, privacyBlocked, splitPlaceholders } from '../app/lib/privacy';
import { LAST_UPDATED, PRIVACY_SECTIONS } from '../app/lib/privacy-content';

const ROOT = resolve(__dirname, '..', '..', '..');
const SECTION_IDS = [
  'who',
  'collect',
  'not-collected',
  'retention',
  'processors',
  'email',
  'mcp',
  'deleting',
  'cookies',
  'changes',
];

describe('privacy page', () => {
  const html = renderToString(<Privacy />);

  it('renders every section and the date, with no third-party assets', () => {
    for (const s of PRIVACY_SECTIONS) expect(html).toContain(`id="privacy-${s.id}"`);
    expect(html).toContain(`Last updated <!-- -->${LAST_UPDATED}`);
    expect(html).not.toMatch(/<script|<img|<link|src="|style=/);
  });

  it('highlights owner placeholders', () => {
    expect(html).toMatch(/<mark class="owner-placeholder">\[\[OWNER: /);
  });

  it('is linked from the footer', () => {
    const f = renderToString(
      <StaticRouter location="/">
        <Footer sourceCount={1} />
      </StaticRouter>,
    ).replace(/ data-discover="true"/g, '');
    expect(f).toContain('<a href="/privacy">Privacy</a>');
  });
});

describe('owner placeholder guard', () => {
  it('splits placeholders from text', () => {
    expect(splitPlaceholders('a [[OWNER: x]] b')).toEqual([
      { text: 'a ', placeholder: false },
      { text: '[[OWNER: x]]', placeholder: true },
      { text: ' b', placeholder: false },
    ]);
  });

  it('blocks production while a placeholder remains, and only production', () => {
    expect(ownerPlaceholders().length).toBeGreaterThan(0);
    expect(privacyBlocked('production')).toBe(true);
    expect(privacyBlocked('staging')).toBe(false);
    expect(privacyBlocked('local')).toBe(false);
    expect(privacyBlocked(undefined)).toBe(false);
  });

  it('lets production through once none remain', () => {
    const done = PRIVACY_SECTIONS.map((s) => ({
      ...s,
      statements: s.statements.map((st) => ({ ...st, text: st.text.replace(/\[\[OWNER:[^\]]*\]\]/g, 'x') })),
    }));
    expect(privacyBlocked('production', done)).toBe(false);
  });

  // The release gate: run with TI_ENV=production, this fails until the owner has filled every decision.
  it.runIf(process.env.TI_ENV === 'production')('has no [[OWNER: placeholder in production', () => {
    expect(ownerPlaceholders()).toEqual([]);
  });
});

describe('statement references', () => {
  it('covers every section', () => {
    expect(PRIVACY_SECTIONS.map((s) => s.id)).toEqual(SECTION_IDS);
    for (const s of PRIVACY_SECTIONS) expect(s.statements.length, s.id).toBeGreaterThan(0);
  });

  it('gives every statement a reference to a real line', () => {
    for (const s of PRIVACY_SECTIONS)
      for (const st of s.statements) {
        expect(st.refs.length, st.text).toBeGreaterThan(0);
        for (const ref of st.refs) {
          if (ref === 'owner-decision') {
            expect(st.text).toContain('[[OWNER:');
            continue;
          }
          const m = /^(.+):(\d+)(?:-(\d+))?$/.exec(ref);
          expect(m, ref).not.toBeNull();
          const file = resolve(ROOT, m?.[1] ?? '');
          expect(existsSync(file), ref).toBe(true);
          const lines = readFileSync(file, 'utf8').split('\n').length;
          expect(Number(m?.[3] ?? m?.[2]), ref).toBeLessThanOrEqual(lines);
        }
      }
  });
});
