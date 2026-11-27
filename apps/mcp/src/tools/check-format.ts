import {
  type CheckResponse,
  canonicalEcosystem,
  ECOSYSTEMS,
  normaliseName,
  parsePurl,
} from '@ti/core/packages';
import { CAPS, clean } from '../clean';
import { ENTRY_ID } from '../input';
import { mtiLink } from '../links';
import { arr, bool, COMMON_OUT, int, nstr, num, obj, root, str } from '../schema';
import { credits, list, matching, numOrNull, rec, sources, VERSION_RE } from './common';

export const SIGNALS = ['exploited_wild', 'ransomware', 'malicious', 'public_exploit', 'poc', 'detection'];
export const PRIORITIES = ['fix_now', 'fix_soon', 'plan', 'note'] as const;
export const NOTE_NO_RECORD = 'No record means MTI has no record as of asOf. It does not mean safe.';
export const NOTE_REACH = 'Reachability is not checked.';
const NOTE_FIXED = 'Some fixed versions were dropped because they were not in a known format.';

export const pkgOut = obj({ ecosystem: str(40), name: str(214), version: str(128) });
export const pkgIn = {
  oneOf: [
    obj({
      ecosystem: { type: 'string', enum: [...ECOSYSTEMS] },
      name: str(214, { minLength: 1 }),
      version: str(128, { minLength: 1 }),
    }),
    obj({ purl: str(512, { minLength: 5, pattern: '^pkg:' }) }),
  ],
};

export type Ref = { ecosystem: string; name: string; version: string };
export const refKey = (r: Ref) => JSON.stringify([r.ecosystem, r.version, r.name]);

function pkg(v: unknown): Ref | null {
  const p = rec(v);
  const ecosystem = typeof p.ecosystem === 'string' ? canonicalEcosystem(p.ecosystem) : null;
  if (!ecosystem || typeof p.name !== 'string' || typeof p.version !== 'string') return null;
  if (p.name.length > 214 || p.version.length > 128) return null;
  return { ecosystem, name: p.name, version: p.version };
}

/**
 * The caller's own packages by their normalised identity. An answer entry is shown only if it matches one of
 * these, and then the caller's own text is what goes out, never a string that came back from ti-api.
 * The value is the position of the first package with that identity.
 */
export function callerPackages(input: unknown[]): Map<string, { ref: Ref; index: number }> {
  const own = new Map<string, { ref: Ref; index: number }>();
  for (const [index, p] of input.entries()) {
    const r = rec(p);
    let ref: Ref | null = null;
    if (typeof r.purl === 'string') {
      const parsed = parsePurl(r.purl);
      if (parsed.ok) ref = parsed.ref;
    } else if (
      typeof r.ecosystem === 'string' &&
      typeof r.name === 'string' &&
      typeof r.version === 'string'
    ) {
      const eco = canonicalEcosystem(r.ecosystem);
      const name = eco ? normaliseName(eco, r.name) : null;
      if (eco && name) ref = { ecosystem: eco, name, version: r.version };
    }
    if (ref && !own.has(refKey(ref))) own.set(refKey(ref), { ref, index });
  }
  return own;
}

export type CheckResultOut = {
  package: Ref;
  priority: (typeof PRIORITIES)[number];
  upgradeTo: string | null;
  upgradeNote: string | null;
  matches: Record<string, unknown>[];
};
export type Rejected = { index: number; reason: string };

export interface FormattedCheck {
  results: { r: CheckResultOut; index: number }[];
  noRecord: { n: Ref; index: number }[];
  rejected: Rejected[];
  summary: Record<(typeof PRIORITIES)[number], number>;
  checked: number | null;
  matched: number | null;
  asOf: unknown;
  credits: ReturnType<typeof credits>;
  notes: string[];
}

/**
 * Turns one ti-api check answer into the tool's shape. Only the caller's own package text goes out. Shared by
 * the one-call path and the long-check runner, so both give the same answer for the same input.
 */
export function formatCheck(
  apiBody: unknown,
  input: unknown[],
  env: Parameters<typeof mtiLink>[0],
): FormattedCheck {
  const api = rec(apiBody);
  const own = callerPackages(input);
  const ownPkg = (v: unknown): { ref: Ref; index: number } | null => {
    const p = pkg(v);
    const mine = p
      ? own.get(refKey({ ...p, name: normaliseName(p.ecosystem as never, p.name) ?? p.name }))
      : null;
    return mine ? { ref: { ...mine.ref }, index: mine.index } : null;
  };
  const notes = [NOTE_NO_RECORD, NOTE_REACH];

  const results = list(api.results).flatMap((r) => {
    const x = rec(r);
    const mine = ownPkg(x.package);
    const priority = PRIORITIES.find((q) => q === x.priority);
    if (!mine || !priority) return [];
    const fixed = (v: unknown) => {
      if (v === null || v === undefined) return null;
      const m = matching(v, VERSION_RE);
      if (!m && !notes.includes(NOTE_FIXED)) notes.push(NOTE_FIXED);
      return m;
    };
    const matches = list(x.matches).flatMap((m) => {
      const y = rec(m);
      const id = matching(y.id, ENTRY_ID);
      const url = id ? mtiLink(env, 'entry', id) : null;
      if (!id || !url) return [];
      const title = clean(y.title, CAPS.title);
      return [
        {
          id,
          url,
          fixedIn: fixed(y.fixedIn),
          signals: list(y.signals).filter((s): s is string => typeof s === 'string' && SIGNALS.includes(s)),
          cvss: numOrNull(y.cvss),
          epss: numOrNull(y.epss),
          sources: sources(y.sources),
          ...(title ? { untrusted: { title } } : {}),
        },
      ];
    });
    return [
      {
        r: {
          package: mine.ref,
          priority,
          upgradeTo: fixed(x.upgradeTo),
          upgradeNote: clean(x.upgradeNote, CAPS.title),
          matches: matches.slice(0, 50),
        },
        index: mine.index,
      },
    ];
  });
  const noRecord = list(api.noRecord).flatMap((v) => {
    const mine = ownPkg(v);
    return mine ? [{ n: mine.ref, index: mine.index }] : [];
  });
  const rejected = list(api.rejected).flatMap((v) => {
    const r = rec(v);
    return Number.isInteger(r.index) && typeof r.reason === 'string' && /^[a-z_]{1,40}$/.test(r.reason)
      ? [{ index: r.index as number, reason: r.reason }]
      : [];
  });
  const sm = rec(api.summary);
  const summary = Object.fromEntries(
    PRIORITIES.map((k) => [k, Number.isInteger(sm[k]) ? (sm[k] as number) : 0]),
  ) as FormattedCheck['summary'];
  return {
    results,
    noRecord,
    rejected,
    summary,
    checked: Number.isInteger(api.checked) ? (api.checked as number) : null,
    matched: Number.isInteger(api.matched) ? (api.matched as number) : null,
    asOf: api.asOf,
    credits: credits(api.credits),
    notes,
  };
}
export type { CheckResponse };

export const CHECK_OUTPUT_SCHEMA = root(
  obj({
    ...COMMON_OUT,
    checked: int(),
    matched: int(),
    summary: obj({ fix_now: int(), fix_soon: int(), plan: int(), note: int() }),
    results: arr(
      obj({
        package: pkgOut,
        priority: { type: 'string', enum: [...PRIORITIES] },
        upgradeTo: nstr(64),
        upgradeNote: nstr(200),
        matches: arr(
          obj(
            {
              id: str(64),
              url: str(300),
              fixedIn: nstr(64),
              signals: arr(str(40), 6),
              cvss: num(),
              epss: num(),
              sources: arr(str(64), 20),
              untrusted: obj({ title: nstr(CAPS.title) }),
            },
            ['id', 'url', 'fixedIn', 'signals', 'cvss', 'epss', 'sources'],
          ),
          50,
        ),
      }),
      20_000,
    ),
    noRecord: arr(pkgOut, 20_000),
    rejected: arr(obj({ index: int(), reason: str(40) }), 20_000),
    truncated: bool(),
    nextCursor: nstr(512),
  }),
);
