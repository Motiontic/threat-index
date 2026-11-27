import type { Credit, EntryAdvisory, EntryPreview } from '@ti/core/api';
import { type DisplayMode, displayMode } from '@ti/core/licence';
import { readSourceSettings } from '@ti/core/settings';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import type { Bindings } from './env';

/** Fields a visitor may see. Everything else needs a free account. */
export const PREVIEW_FIELDS = ['key', 'kind', 'title', 'summary', 'published', 'cvss', 'kev_added'] as const;

export function previewEntry(row: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(PREVIEW_FIELDS.map((f) => [f, row[f] ?? null]));
}

/** Bindings the public read routes use. Folds into `Bindings` (lib/env.ts) later; both are in wrangler.jsonc. */
export type ReadEnv = Bindings & { DB_SIGNALS: D1Database; SETTINGS: KVNamespace };

export interface VulnRow {
  key: string;
  kind: string;
  title: string;
  summary: string | null;
  published: string | null;
  modified: string | null;
  cvss: number | null;
  cvss_version: string | null;
  cvss_source: string | null;
  cvss_from?: string | null;
  cwe: string | null;
  kev_added: string | null;
  ransomware: number;
  epss: number | null;
  sources: string | null;
}

export interface AdvisoryRow {
  source: string;
  source_id: string;
  vuln_key: string | null;
  status: string;
  published: string | null;
  modified: string | null;
  url: string | null;
}

export type DisplayMap = ReadonlyMap<string, DisplayMode>;

/** displayMode(registry licence, KV override) for each id; ids not in SOURCE_BY_ID map to 'hidden'. */
export async function displayFor(kv: KVNamespace, ids: readonly string[]): Promise<DisplayMap> {
  const unique = [...new Set(ids)];
  const known = unique.filter((id) => SOURCE_BY_ID.has(id));
  const settings = known.length ? await readSourceSettings(kv, known) : new Map();
  const out = new Map<string, DisplayMode>();
  for (const id of unique) {
    const src = SOURCE_BY_ID.get(id);
    out.set(id, src ? displayMode(src.licence, settings.get(id)?.display) : 'hidden');
  }
  return out;
}

/** Parsed JSON string array; anything else is `[]`. */
export function parseStringArray(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) && v.every((x) => typeof x === 'string') ? (v as string[]) : [];
  } catch {
    return [];
  }
}

const opt = <T>(v: T | null | undefined): T | undefined => (v === null || v === undefined ? undefined : v);

export function toPreview(
  row: VulnRow,
  aliases: string[],
  exploited: boolean,
  credits: Credit[],
): EntryPreview {
  const out: EntryPreview = {
    key: row.key,
    kind: row.kind,
    title: row.title,
    summary: row.summary ?? '',
    aliases,
    exploited,
    credits,
  };
  if (opt(row.published) !== undefined) out.published = row.published as string;
  if (opt(row.modified) !== undefined) out.modified = row.modified as string;
  if (opt(row.cvss) !== undefined) out.cvss = row.cvss as number;
  if (opt(row.cvss_version) !== undefined) out.cvssVersion = row.cvss_version as string;
  if (opt(row.cvss) !== undefined && opt(row.cvss_source) !== undefined)
    out.cvssSource = row.cvss_source as string;
  if (opt(row.kev_added) !== undefined) out.kevAdded = row.kev_added as string;
  if (opt(row.epss) !== undefined) out.epss = row.epss as number;
  return out;
}

/** Null when hidden. `link` keeps only the link fields. */
export function toAdvisory(row: AdvisoryRow, mode: DisplayMode): EntryAdvisory | null {
  if (mode === 'hidden') return null;
  const out: EntryAdvisory = {
    source: row.source,
    sourceId: row.source_id,
    status: row.status,
    display: mode,
  };
  if (opt(row.published) !== undefined) out.published = row.published as string;
  if (opt(row.url) !== undefined) out.url = row.url as string;
  if (mode === 'full' && opt(row.modified) !== undefined) out.modified = row.modified as string;
  return out;
}
