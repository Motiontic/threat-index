import { canonicalEcosystem, ECOSYSTEMS, normaliseName, parsePurl } from '@ti/core/packages';
import { ENTRY_ID, normaliseEntryId } from '../input';
import { obj, str } from '../schema';

export type WatchInput = { ecosystem?: string; name?: string; purl?: string; entryId?: string };
export type WatchTarget =
  | { kind: 'package'; ecosystem: string; name: string }
  | { kind: 'entry'; entryId: string };

/** Exactly one of three shapes. No list: one item per call, so there is no bulk add or bulk remove. */
export const WATCH_INPUT = {
  oneOf: [
    obj({
      ecosystem: { type: 'string', enum: [...ECOSYSTEMS] },
      name: str(214, { minLength: 1 }),
    }),
    obj({ purl: str(512, { minLength: 5, pattern: '^pkg:' }) }),
    obj({ entryId: str(64, { minLength: 3, pattern: '^[A-Za-z0-9._:-]+$' }) }),
  ],
  type: 'object',
  additionalProperties: false,
  properties: {
    ecosystem: { type: 'string', enum: [...ECOSYSTEMS] },
    name: str(214, { minLength: 1 }),
    purl: str(512, { minLength: 5, pattern: '^pkg:' }),
    entryId: str(64, { minLength: 3, pattern: '^[A-Za-z0-9._:-]+$' }),
  },
};

export type ParsedTarget = { ok: true; target: WatchTarget } | { ok: false; field: string };

/** Checks the input is exactly one of the three shapes and normalises it the way ti-api does. */
export function parseTarget(args: WatchInput): ParsedTarget {
  const given = (['ecosystem', 'name', 'purl', 'entryId'] as const).filter((k) => args[k] !== undefined);
  const key = given.join(',');
  if (key === 'ecosystem,name') {
    const ecosystem = canonicalEcosystem(String(args.ecosystem));
    const name = ecosystem ? normaliseName(ecosystem, String(args.name)) : null;
    if (!ecosystem) return { ok: false, field: 'ecosystem' };
    if (!name || name.length > 214) return { ok: false, field: 'name' };
    return { ok: true, target: { kind: 'package', ecosystem, name } };
  }
  if (key === 'purl') {
    const p = parsePurl(String(args.purl));
    if (!p.ok || p.ref.name.length > 214) return { ok: false, field: 'purl' };
    return { ok: true, target: { kind: 'package', ecosystem: p.ref.ecosystem, name: p.ref.name } };
  }
  if (key === 'entryId') {
    const id = normaliseEntryId(String(args.entryId));
    return ENTRY_ID.test(id)
      ? { ok: true, target: { kind: 'entry', entryId: id } }
      : { ok: false, field: 'entryId' };
  }
  return { ok: false, field: given[0] ?? 'input' };
}

export const packagePath = (t: { ecosystem: string; name: string }): string =>
  `/v1/me/watch/packages/${encodeURIComponent(t.ecosystem)}/${encodeURIComponent(t.name)}`;
export const entryPath = (t: { entryId: string }): string => `/v1/me/watch/${encodeURIComponent(t.entryId)}`;
export const targetPath = (t: WatchTarget): string => (t.kind === 'package' ? packagePath(t) : entryPath(t));
