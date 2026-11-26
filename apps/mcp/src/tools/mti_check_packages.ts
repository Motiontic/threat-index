import {
  CheckRequestSchema,
  type CheckResponse,
  canonicalEcosystem,
  ECOSYSTEMS,
  normaliseName,
  parsePurl,
} from '@ti/core/packages';
import { CAPS, clean } from '../clean';
import { openCursor, sealCursor } from '../cursor';
import { ENTRY_ID } from '../input';
import { mtiLink } from '../links';
import { arr, bool, COMMON_OUT, int, nstr, num, obj, root, str } from '../schema';
import { credits, list, matching, numOrNull, rec, sources, VERSION_RE } from './common';
import { apiJson, asOfFrom, MAX_STRUCTURED_CHARS, type ToolDef } from './shared';

const SIGNALS = ['exploited_wild', 'ransomware', 'malicious', 'public_exploit', 'poc', 'detection'];
const PRIORITIES = ['fix_now', 'fix_soon', 'plan', 'note'] as const;
const NOTE_NO_RECORD = 'No record means MTI has no record as of asOf. It does not mean safe.';
const NOTE_REACH = 'Reachability is not checked.';

type Args = { packages: unknown[]; cursor?: string };

const pkgOut = obj({ ecosystem: str(40), name: str(214), version: str(128) });
const pkgIn = {
  oneOf: [
    obj({
      ecosystem: { type: 'string', enum: [...ECOSYSTEMS] },
      name: str(214, { minLength: 1 }),
      version: str(128, { minLength: 1 }),
    }),
    obj({ purl: str(512, { minLength: 5, pattern: '^pkg:' }) }),
  ],
};

function pkg(v: unknown): { ecosystem: string; name: string; version: string } | null {
  const p = rec(v);
  const ecosystem = typeof p.ecosystem === 'string' ? canonicalEcosystem(p.ecosystem) : null;
  if (!ecosystem || typeof p.name !== 'string' || typeof p.version !== 'string') return null;
  if (p.name.length > 214 || p.version.length > 128) return null;
  return { ecosystem, name: p.name, version: p.version };
}

type Ref = { ecosystem: string; name: string; version: string };
const refKey = (r: Ref) => JSON.stringify([r.ecosystem, r.version, r.name]);

/**
 * The caller's own packages by their normalised identity. An answer entry is shown only if it matches one of
 * these, and then the caller's own text is what goes out, never a string that came back from ti-api.
 */
function callerPackages(input: unknown[]): Map<string, Ref> {
  const own = new Map<string, Ref>();
  for (const p of input) {
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
    if (ref && !own.has(refKey(ref))) own.set(refKey(ref), ref);
  }
  return own;
}

export const tool: ToolDef<Args> = {
  name: 'mti_check_packages',
  enabled: true,
  title: 'Check packages',
  description:
    'Checks package versions against MTI records of known vulnerabilities, malicious packages and exploitation signals. Takes up to 1,000 packages, each as ecosystem, name and version, or as a purl. Returns a priority per package (fix_now, fix_soon, plan or note), the version that fixes the matches where one is known, and the matching records. A package with no match is listed under noRecord, which means MTI has no record as of asOf, not that the package is safe. Reachability is not checked.',
  inputSchema: root(obj({ packages: { ...arr(pkgIn, 1000), minItems: 1 }, cursor: str(512) }, ['packages'])),
  outputSchema: root(
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
        1000,
      ),
      noRecord: arr(pkgOut, 1000),
      rejected: arr(obj({ index: int(), reason: str(40) }), 1000),
      truncated: bool(),
      nextCursor: nstr(512),
    }),
  ),
  async run(args, deps, signal) {
    const secrets = [deps.env.MCP_HMAC_SECRET, deps.env.MCP_HMAC_SECRET_NEXT];
    let offset = 0;
    if (args.cursor !== undefined) {
      const st = await openCursor(
        secrets,
        'mti_check_packages',
        args as Record<string, unknown>,
        args.cursor,
        deps.identity.sub,
      );
      if (!st || !('o' in st)) return { ok: false, code: 'invalid_argument', field: 'cursor' };
      offset = st.o;
    }
    const body = {
      packages: args.packages.map((p) => {
        const r = rec(p);
        return 'purl' in r ? { purl: r.purl } : { ecosystem: r.ecosystem, name: r.name, version: r.version };
      }),
    };
    if (!CheckRequestSchema.safeParse(body).success)
      return { ok: false, code: 'invalid_argument', field: 'packages' };

    const res = await apiJson<CheckResponse>(
      deps,
      { method: 'POST', path: '/v1/packages/check', body },
      signal,
    );
    if (!res.ok)
      return {
        ok: false,
        code: res.code,
        retryAfter: res.retryAfter,
        ...(res.code === 'invalid_argument' ? { field: 'packages' } : {}),
      };
    const api = rec(res.body);
    const own = callerPackages(args.packages);
    const ownPkg = (v: unknown): Ref | null => {
      const p = pkg(v);
      const mine = p
        ? own.get(refKey({ ...p, name: normaliseName(p.ecosystem as never, p.name) ?? p.name }))
        : null;
      return mine ? { ...mine } : null;
    };
    const notes = [NOTE_NO_RECORD, NOTE_REACH];

    const results = list(api.results).flatMap((r) => {
      const x = rec(r);
      const p = ownPkg(x.package);
      const priority = PRIORITIES.find((q) => q === x.priority);
      if (!p || !priority) return [];
      const fixed = (v: unknown) => {
        if (v === null || v === undefined) return null;
        const m = matching(v, VERSION_RE);
        if (
          !m &&
          !notes.includes('Some fixed versions were dropped because they were not in a known format.')
        )
          notes.push('Some fixed versions were dropped because they were not in a known format.');
        return m;
      };
      const matches = list(x.matches).flatMap((m) => {
        const y = rec(m);
        const id = matching(y.id, ENTRY_ID);
        const url = id ? mtiLink(deps.env, 'entry', id) : null;
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
          package: p,
          priority,
          upgradeTo: fixed(x.upgradeTo),
          upgradeNote: clean(x.upgradeNote, CAPS.title),
          matches: matches.slice(0, 50),
        },
      ];
    });
    const noRecord = list(api.noRecord).flatMap((v) => {
      const p = ownPkg(v);
      return p ? [p] : [];
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
    );

    // One sequence, results then noRecord, so a cursor offset names a place in it.
    const seq: { r?: (typeof results)[number]; n?: (typeof noRecord)[number] }[] = [
      ...results.map((r) => ({ r })),
      ...noRecord.map((n) => ({ n })),
    ];
    const page = seq.slice(offset);
    const build = (n: number, more: boolean) => ({
      asOf: asOfFrom(api.asOf, deps),
      checked: Number.isInteger(api.checked) ? (api.checked as number) : args.packages.length,
      matched: Number.isInteger(api.matched) ? (api.matched as number) : results.length,
      summary,
      results: page.slice(0, n).flatMap((s) => (s.r ? [s.r] : [])),
      noRecord: page.slice(0, n).flatMap((s) => (s.n ? [s.n] : [])),
      rejected: offset === 0 ? rejected : [],
      truncated: more,
      credits: credits(api.credits),
      notes,
    });
    const size = (n: number, more: boolean) =>
      JSON.stringify({ ...build(n, more), nextCursor: 'x'.repeat(480) }).length;
    let kept = page.length;
    if (size(kept, false) > MAX_STRUCTURED_CHARS) {
      let lo = 0;
      let hi = page.length;
      while (lo < hi) {
        const mid = Math.ceil((lo + hi) / 2);
        if (size(mid, true) <= MAX_STRUCTURED_CHARS) lo = mid;
        else hi = mid - 1;
      }
      kept = Math.max(lo, 1);
    }
    const more = kept < page.length;
    const nextCursor =
      more && deps.env.MCP_HMAC_SECRET
        ? await sealCursor(
            deps.env.MCP_HMAC_SECRET,
            'mti_check_packages',
            args as Record<string, unknown>,
            {
              o: offset + kept,
            },
            deps.identity.sub,
          )
        : null;
    const data = { ...build(kept, more), nextCursor };
    const ecos = [
      ...new Set([...results.map((r) => r.package.ecosystem), ...noRecord.map((n) => n.ecosystem)]),
    ].sort();
    deps.stats.ecosystems = ecos.join(',');
    return { ok: true, data, nIn: args.packages.length, nOut: kept };
  },
};
