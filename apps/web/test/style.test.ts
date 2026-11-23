import { describe, expect, it } from 'vitest';
import { appFiles } from './read-app';

// Built from pieces so a repo-wide search for the forbidden markup finds only real uses.
const FORBIDDEN_FORM_ATTRS = new RegExp(
  ['type="pass' + 'word"', '-pass' + 'word"', 'method="po' + 'st"'].join('|'),
  'i',
);

const entries = appFiles();
const notTokens = entries.filter(([path]) => path !== 'app/styles/tokens.css');

describe('style rules', () => {
  it('finds the app files', () => {
    expect(entries.length).toBeGreaterThan(20);
    expect(entries.some(([p]) => p === 'app/styles/tokens.css')).toBe(true);
  });

  it('has no colour literal outside tokens.css', () => {
    const literal = /#[0-9a-fA-F]{3,8}\b|\b(?:rgb|rgba|hsl|hsla|oklch|oklab|lab|lch|hwb)\(/;
    const offenders = notTokens.filter(([, text]) => literal.test(text)).map(([p]) => p);
    expect(offenders).toEqual([]);
  });

  it('uses no named colours in CSS declarations', () => {
    const named =
      /(?:color|background|border[a-z-]*|outline|fill|stroke)\s*:\s*(?:white|black|red|blue|green|gray|grey|orange)\b/i;
    expect(notTokens.filter(([p, t]) => p.endsWith('.css') && named.test(t)).map(([p]) => p)).toEqual([]);
  });

  it('has no style attribute (the CSP blocks them)', () => {
    const offenders = entries
      .filter(([p]) => p.endsWith('.tsx'))
      .filter(([, text]) => /\bstyle\s*=\s*[{"']/.test(text))
      .map(([p]) => p);
    expect(offenders).toEqual([]);
  });

  it('has exactly one dangerouslySetInnerHTML, in the JSON-LD component', () => {
    const uses = entries.filter(([p, text]) => p.endsWith('.tsx') && /dangerouslySetInnerHTML=/.test(text));
    expect(uses.map(([p]) => p)).toEqual(['app/lib/seo.tsx']);
    expect(uses[0]?.[1].match(/dangerouslySetInnerHTML=/g)).toHaveLength(1);
  });

  it('calls fetch only in api.server.ts and env.API only in data.server.ts', () => {
    const fetchers = entries.filter(([, text]) => /\bfetch\(/.test(text)).map(([p]) => p);
    expect(fetchers).toEqual(['app/data/api.server.ts']);
    const bindings = entries.filter(([, text]) => /env\.API/.test(text)).map(([p]) => p);
    expect(bindings).toEqual(['app/data/data.server.ts']);
  });

  it('has no sample-data constant or changes fixture', () => {
    const offenders = entries.filter(([, text]) => /SAMPLE_DATA|changes\.json/.test(text)).map(([p]) => p);
    expect(offenders).toEqual([]);
  });

  it('collects no passwords and posts no forms', () => {
    const offenders = entries.filter(([, text]) => FORBIDDEN_FORM_ATTRS.test(text)).map(([p]) => p);
    expect(offenders).toEqual([]);
  });
});
