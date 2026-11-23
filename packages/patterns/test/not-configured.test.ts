import type { PatternName } from '@ti/sources/registry';
import { SOURCE_BY_ID, SOURCES } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { patternFor } from '../src/by-name';
import { PatternError } from '../src/errors';
import { makeCtx } from './helpers';

const FIRST: Record<PatternName, string> = {
  git: 'cve-list',
  changelist: 'osv',
  since: 'nvd',
  fingerprint: 'cisa-kev',
  feed: 'cisa-advisories',
  page: 'cert-in',
  heavy: 'cwe',
};

describe('a source without a pull block', () => {
  it.each(Object.entries(FIRST))(
    '%s: check() and fetch() throw not-configured and make no request',
    async (name, id) => {
      const source = SOURCE_BY_ID.get(id);
      if (!source) throw new Error(id);
      const mod = patternFor(name as PatternName);
      const h = makeCtx({ source: { ...source, pull: undefined } });
      for (const call of [mod.check, mod.fetch]) {
        const err = await call(h.ctx).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(PatternError);
        expect(err).toMatchObject({ code: 'not-configured', retryable: false });
      }
      expect(h.requests).toHaveLength(0);
    },
  );

  it('covers every pattern with a registered source', () => {
    expect(new Set(SOURCES.map((s) => s.pattern))).toEqual(new Set(Object.keys(FIRST)));
  });
});

describe('a block for another pattern', () => {
  it('is ignored: each pattern reads only its own block', async () => {
    const source = SOURCE_BY_ID.get('osv');
    if (!source) throw new Error('osv');
    const h = makeCtx({ source: { ...source, pull: { git: { repo: 'a/b', include: ['*'] } } } });
    await expect(patternFor('changelist').fetch(h.ctx)).rejects.toMatchObject({ code: 'not-configured' });
  });
});

describe('a link-only source', () => {
  it('is not-configured for patterns other than feed and page', async () => {
    const osv = SOURCE_BY_ID.get('osv');
    if (!osv) throw new Error('osv');
    const h = makeCtx({
      source: {
        ...osv,
        licence: 'link',
        pull: {
          changelist: {
            listUrl: 'https://x.test/l.csv',
            timeColumn: 0,
            refColumn: 1,
            itemUrl: 'https://x.test/{ref}',
          },
        },
      },
    });
    await expect(patternFor('changelist').fetch(h.ctx)).rejects.toMatchObject({ code: 'not-configured' });
    expect(h.requests).toHaveLength(0);
  });
});
