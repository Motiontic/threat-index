import type { Credit, EntryAdvisory, EntryChange, EntryFull, EntryResponse, EntrySignal } from '@ti/core/api';
import { rawReceiptKey } from '@ti/core/r2-keys';
import { Hono } from 'hono';
import { requireUser } from '../lib/auth';
import { cachedPublic, guarded, isSignedIn } from '../lib/cache';
import { creditsFor } from '../lib/credits';
import type { AppEnv } from '../lib/env';
import {
  type AdvisoryRow,
  type DisplayMap,
  displayFor,
  parseStringArray,
  type ReadEnv,
  toAdvisory,
  toPreview,
  type VulnRow,
} from '../lib/preview';
import { resolveKey, validId } from '../lib/resolve-key';

const route = new Hono<AppEnv>();

const ENTRY_TTL = 300;
const CHANGES_WINDOW_MS = 90 * 24 * 3600 * 1000;
const RECEIPT_SOURCES_MAX = 10;
const RUNS_PER_SOURCE = 2;

interface SignalRow {
  kind: string;
  source: string;
  ref: string;
  first_seen: string;
  url: string | null;
}
interface ChangeRow {
  kind: string;
  old: string | null;
  new: string | null;
  at: string;
  source: string | null;
}

export interface ReceiptsResponse {
  key: string;
  exact: false; // per-entry run ids are not stored yet
  note: string;
  receipts: {
    sourceId: string;
    runId: string;
    status: string;
    startedAt: string;
    finishedAt?: string;
    objects: { key: string; uploaded: string; size: number }[];
  }[];
  credits: Credit[];
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const defined = <T>(v: T | null): T | undefined => (v === null ? undefined : v);

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Milliseconds since the epoch from the first 10 Crockford base32 characters of a ULID. NaN if invalid. */
export function decodeUlidTime(ulid: string): number {
  if (ulid.length < 10) return Number.NaN;
  let ms = 0;
  for (const ch of ulid.slice(0, 10).toUpperCase()) {
    const v = CROCKFORD.indexOf(ch);
    if (v < 0) return Number.NaN;
    ms = ms * 32 + v;
  }
  return ms;
}

/** Everything the entry routes know about one key, with licence display rules already applied. */
async function loadEntry(env: ReadEnv, key: string, full: boolean) {
  const row = await env.DB_VULNS.prepare('SELECT * FROM vulns WHERE key = ?1').bind(key).first<VulnRow>();
  if (!row) return null;

  const advRows =
    (
      await env.DB_ADVISORIES.prepare('SELECT * FROM advisories WHERE vuln_key = ?1 LIMIT 200')
        .bind(key)
        .all<AdvisoryRow>()
    ).results ?? [];
  const signalRows = full
    ? ((
        await env.DB_SIGNALS.prepare('SELECT * FROM signals WHERE vuln_key = ?1 LIMIT 200')
          .bind(key)
          .all<SignalRow>()
      ).results ?? [])
    : ((
        await env.DB_SIGNALS.prepare(
          "SELECT kind, source, ref, first_seen, url FROM signals WHERE vuln_key = ?1 AND kind = 'exploited_wild' LIMIT 200",
        )
          .bind(key)
          .all<SignalRow>()
      ).results ?? []);
  const changeRows = full
    ? ((
        await env.DB_SIGNALS.prepare(
          'SELECT kind, old, new, at, source FROM changes WHERE entity_key = ?1 AND at >= ?2 ORDER BY at DESC LIMIT 20',
        )
          .bind(key, new Date(Date.now() - CHANGES_WINDOW_MS).toISOString())
          .all<ChangeRow>()
      ).results ?? [])
    : [];

  const sources = parseStringArray(row.sources);
  const realAdvs = advRows.filter((a) => a.source !== 'alias');
  const aliasRows = advRows.filter((a) => a.source === 'alias');
  const display: DisplayMap = await displayFor(env.SETTINGS, [
    ...sources,
    ...(row.cvss_source ? [row.cvss_source] : []),
    ...realAdvs.map((a) => a.source),
    ...signalRows.map((s) => s.source),
    ...changeRows.flatMap((c) => (c.source ? [c.source] : [])),
  ]);
  const visible = (id: string | null) => id !== null && (display.get(id) ?? 'hidden') !== 'hidden';

  const hiddenIds = new Set(realAdvs.filter((a) => !visible(a.source)).map((a) => a.source_id));
  const aliases = [
    ...new Set([
      ...aliasRows.map((a) => a.source_id),
      ...realAdvs.filter((a) => visible(a.source)).map((a) => a.source_id),
    ]),
  ]
    .filter((id) => id !== key && !hiddenIds.has(id))
    .sort(cmp);

  const visibleSignals = signalRows.filter((s) => visible(s.source));
  const exploited =
    Boolean(row.kev_added) || row.ransomware === 1 || visibleSignals.some((s) => s.kind === 'exploited_wild');

  const cvssHidden = row.cvss_source ? !visible(row.cvss_source) : false;
  const base: VulnRow = cvssHidden ? { ...row, cvss: null, cvss_version: null } : row;

  const advisories: EntryAdvisory[] = realAdvs
    .map((a) => toAdvisory(a, display.get(a.source) ?? 'hidden'))
    .filter((a): a is EntryAdvisory => a !== null)
    .sort((a, b) => cmp(a.source, b.source) || cmp(a.sourceId, b.sourceId));
  const signals: EntrySignal[] = visibleSignals
    .map((s) => {
      const out: EntrySignal = { kind: s.kind, source: s.source, ref: s.ref, firstSeen: s.first_seen };
      const url = defined(s.url);
      if (url !== undefined) out.url = url;
      return out;
    })
    .sort((a, b) => cmp(a.kind, b.kind) || cmp(a.firstSeen, b.firstSeen));
  const changes: EntryChange[] = changeRows
    .filter((c) => c.source === null || visible(c.source))
    .map((c) => {
      const out: EntryChange = { kind: c.kind, at: c.at };
      if (c.old !== null) out.old = c.old;
      if (c.new !== null) out.new = c.new;
      if (c.source !== null) out.source = c.source;
      return out;
    });

  const baseIds = [...sources, ...(row.cvss_source ? [row.cvss_source] : [])];
  const creditIds = full
    ? [
        ...baseIds,
        ...advisories.map((a) => a.source),
        ...signals.map((s) => s.source),
        ...changes.flatMap((c) => (c.source ? [c.source] : [])),
      ]
    : baseIds;
  const credits = creditsFor(creditIds, display);

  return {
    row: base,
    aliases,
    exploited,
    credits,
    advisories,
    signals,
    changes,
    cwe: parseStringArray(row.cwe),
  };
}

route.get('/v1/entries/:id', (c) =>
  guarded(c, 'GET /v1/entries/:id', async () => {
    const env = c.env as ReadEnv;
    const id = validId(c.req.param('id'));
    if (!id) return c.json({ error: 'bad_id' }, 400);
    const key = await resolveKey(env, id);
    if (!key) return c.json({ error: 'not_found' }, 404);
    const full = isSignedIn(c);
    return cachedPublic(c, ENTRY_TTL, `/v1/entries/${encodeURIComponent(key)}`, async () => {
      const e = await loadEntry(env, key, full);
      if (!e) return c.json({ error: 'not_found' }, 404);
      const preview = toPreview(e.row, e.aliases, e.exploited, e.credits);
      const body: EntryResponse = full
        ? {
            access: 'full',
            entry: {
              ...preview,
              cwe: e.cwe,
              advisories: e.advisories,
              signals: e.signals,
              changes: e.changes,
            } satisfies EntryFull,
          }
        : { access: 'preview', entry: preview };
      return c.json(body);
    });
  }),
);

// Signed in. The latest successful runs of each source with data on this entry, and their R2 objects.
route.get('/v1/entries/:id/receipts', requireUser, (c) =>
  guarded(c, 'GET /v1/entries/:id/receipts', async () => {
    const env = c.env as ReadEnv;
    const id = validId(c.req.param('id'));
    if (!id) return c.json({ error: 'bad_id' }, 400);
    const key = await resolveKey(env, id);
    if (!key) return c.json({ error: 'not_found' }, 404);
    const e = await loadEntry(env, key, true);
    if (!e) return c.json({ error: 'not_found' }, 404);

    const sourceIds = [...new Set(e.credits.map((cr) => cr.sourceId))].slice(0, RECEIPT_SOURCES_MAX);
    const receipts: ReceiptsResponse['receipts'] = [];
    for (const sourceId of sourceIds) {
      const runs =
        (
          await env.DB_CONTROL.prepare(
            `SELECT id, status, started_at, finished_at FROM runs
             WHERE source_id = ?1 AND status IN ('ok','heavy') ORDER BY started_at DESC LIMIT ${RUNS_PER_SOURCE}`,
          )
            .bind(sourceId)
            .all<{ id: string; status: string; started_at: string; finished_at: string | null }>()
        ).results ?? [];
      for (const run of runs) {
        const at = new Date(decodeUlidTime(run.id));
        if (Number.isNaN(at.getTime())) continue;
        // The prefix is the step-0 key minus its step and extension: raw/<source>/<y>/<m>/<d>/<runId>-
        const prefix = rawReceiptKey(sourceId, run.id, 0, at).replace(/0\.ndjson\.gz$/, '');
        const listed = await env.BUCKET.list({ prefix, limit: 20 });
        const out: ReceiptsResponse['receipts'][number] = {
          sourceId,
          runId: run.id,
          status: run.status,
          startedAt: run.started_at,
          objects: listed.objects.map((o) => ({
            key: o.key,
            uploaded: o.uploaded.toISOString(),
            size: o.size,
          })),
        };
        if (run.finished_at) out.finishedAt = run.finished_at;
        receipts.push(out);
      }
    }
    const body: ReceiptsResponse = {
      key,
      exact: false,
      note: 'The latest successful runs of each source with data on this entry. They are not proven to contain it: per-entry run ids are not stored yet. Uploaded times are when R2 stored each object, within seconds of the fetch.',
      receipts,
      credits: e.credits,
    };
    c.header('cache-control', 'private, no-store');
    return c.json(body);
  }),
);

export default route;
