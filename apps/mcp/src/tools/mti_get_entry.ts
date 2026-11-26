import type { EntryResponse } from '@ti/core/api';
import { canonicalEcosystem } from '@ti/core/packages';
import { CAPS, clean } from '../clean';
import { ENTRY_ID, normaliseEntryId } from '../input';
import { mtiLink, sourceLink } from '../links';
import { arr, bool, COMMON_OUT, int, nstr, num, obj, root, str } from '../schema';
import { credits, date, ID_RE, list, matching, numOrNull, rec, SRC_RE, VERSION_RE } from './common';
import { apiJson, asOfFrom, type ToolDef } from './shared';

const NAME_RE = /^[A-Za-z0-9@/._+:-]{1,214}$/;
const SIGNAL_COUNTS = {
  exploited_wild: 'exploitedInWild',
  ransomware: 'ransomware',
  public_exploit: 'publicExploits',
  poc: 'proofsOfConcept',
  detection: 'detections',
} as const;

export const tool: ToolDef<{ id: string }> = {
  name: 'mti_get_entry',
  enabled: true,
  title: 'Get entry',
  description:
    'Returns one MTI record by CVE, GHSA, OSV, MAL or EUVD ID: severity, EPSS, whether it is exploited in the wild, counts of public exploits and proofs of concept, fixed versions per package, advisories and sources. Text written by outside sources is returned under untrusted.',
  inputSchema: root(obj({ id: str(64, { minLength: 3, pattern: '^[A-Za-z0-9._:-]+$' }) })),
  outputSchema: root(
    obj(
      {
        ...COMMON_OUT,
        found: bool(),
        id: str(64),
        key: nstr(128),
        url: nstr(300),
        kind: nstr(32),
        access: { type: 'string', enum: ['full', 'preview'] },
        published: nstr(40),
        modified: nstr(40),
        cvss: num(),
        cvssVersion: nstr(16),
        epss: num(),
        exploited: bool(),
        kevAdded: nstr(40),
        cwe: arr(str(16), 20),
        aliases: arr(str(64), 50),
        exploitation: obj({
          exploitedInWild: int(),
          ransomware: int(),
          publicExploits: int(),
          proofsOfConcept: int(),
          detections: int(),
          sources: arr(str(64), 20),
        }),
        fixes: arr(
          obj({ ecosystem: str(40), name: str(214), introduced: nstr(64), fixed: nstr(64), source: str(64) }),
          50,
        ),
        advisories: arr(
          obj({ source: str(64), sourceId: str(128), status: nstr(32), published: nstr(40), url: nstr(2048) }),
          30,
        ),
        recentChanges: arr(obj({ kind: str(40), at: str(40), source: nstr(64) }), 20),
        untrusted: obj({ title: nstr(CAPS.title), summary: nstr(CAPS.summary) }),
      },
      ['asOf', 'credits', 'notes', 'found', 'id'],
    ),
  ),
  async run(args, deps, signal) {
    const id = normaliseEntryId(args.id);
    if (!ENTRY_ID.test(id)) return { ok: false, code: 'invalid_argument', field: 'id', problem: 'not_an_id' };
    const res = await apiJson<EntryResponse>(deps, { method: 'GET', path: `/v1/entries/${encodeURIComponent(id)}` }, signal);
    if (!res.ok && res.status === 404)
      return { ok: true, data: { found: false, id, asOf: deps.now().toISOString(), credits: [], notes: ['No MTI record for this ID.'] }, nIn: 1, nOut: 0 };
    if (!res.ok) return { ok: false, code: res.code, retryAfter: res.retryAfter, ...(res.code === 'invalid_argument' ? { field: 'id', problem: 'not_an_id' as const } : {}) };
    const top = rec(res.body);
    const e = rec(top.entry);
    const full = top.access === 'full';
    const key = matching(e.key, ID_RE);
    const signals = full ? list(e.signals).map(rec) : [];
    const counts = { exploitedInWild: 0, ransomware: 0, publicExploits: 0, proofsOfConcept: 0, detections: 0 };
    const sigSources = new Set<string>();
    for (const s of signals) {
      const name = SIGNAL_COUNTS[s.kind as keyof typeof SIGNAL_COUNTS];
      if (name) counts[name]++;
      const src = matching(s.source, SRC_RE);
      if (src) sigSources.add(src);
    }
    const advisoriesRaw = full ? list(e.advisories).map(rec) : [];
    const fixes = advisoriesRaw
      .flatMap((a) =>
        list(a.affected).flatMap((x) => {
          const f = rec(x);
          const ecosystem = typeof f.ecosystem === 'string' ? canonicalEcosystem(f.ecosystem) : null;
          const name = matching(f.name, NAME_RE);
          const source = matching(a.source, SRC_RE);
          const introduced = f.introduced === undefined ? null : matching(f.introduced, VERSION_RE);
          const fixed = f.fixed === undefined ? null : matching(f.fixed, VERSION_RE);
          if (!ecosystem || !name || !source) return [];
          if ((f.introduced !== undefined && !introduced) || (f.fixed !== undefined && !fixed)) return [];
          return [{ ecosystem, name, introduced, fixed, source }];
        }),
      )
      .slice(0, 50);
    const advisories = advisoriesRaw
      .flatMap((a) => {
        const source = matching(a.source, SRC_RE);
        const sourceId = matching(a.sourceId, ID_RE);
        if (!source || !sourceId) return [];
        return [{ source, sourceId, status: matching(a.status, /^[a-z_ -]{1,32}$/), published: date(a.published), url: sourceLink(a.url) }];
      })
      .slice(0, 30);
    const recentChanges = (full ? list(e.changes).map(rec) : [])
      .flatMap((c) => {
        const kind = matching(c.kind, /^[a-z_:]{1,40}$/);
        const at = date(c.at);
        return kind && at ? [{ kind, at, source: matching(c.source, SRC_RE) }] : [];
      })
      .slice(0, 20);
    const data = {
      asOf: asOfFrom(undefined, deps),
      credits: credits(e.credits),
      notes: [] as string[],
      found: true,
      id,
      key,
      url: key ? mtiLink(deps.env, 'entry', key) : null,
      kind: matching(e.kind, /^[a-z_]{1,32}$/),
      access: full ? 'full' : 'preview',
      published: date(e.published),
      modified: date(e.modified),
      cvss: numOrNull(e.cvss),
      cvssVersion: matching(e.cvssVersion, /^[A-Za-z0-9.:/]{1,16}$/),
      epss: numOrNull(e.epss),
      exploited: e.exploited === true,
      kevAdded: date(e.kevAdded),
      cwe: list(e.cwe).filter((c): c is string => typeof c === 'string' && /^CWE-\d{1,6}$/.test(c)).slice(0, 20),
      aliases: list(e.aliases).filter((a): a is string => typeof a === 'string' && ENTRY_ID.test(a)).slice(0, 50),
      exploitation: { ...counts, sources: [...sigSources].slice(0, 20) },
      fixes,
      advisories,
      recentChanges,
      untrusted: { title: clean(e.title, CAPS.title), summary: clean(e.summary, CAPS.summary) },
    };
    if (!full) data.notes.push('Only the preview of this record is available to this account.');
    return { ok: true, data, nIn: 1, nOut: 1 };
  },
};
