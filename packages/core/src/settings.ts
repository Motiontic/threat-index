import { z } from 'zod';
import type { DisplayMode } from './licence';

/** KV (`SETTINGS`) keys. Per-source overrides win over the registry without a redeploy. */
export const SOURCE_SETTINGS_PREFIX = 'source:'; // source:<id> → SourceSettings
export const UNKNOWN_FIELDS_PREFIX = 'unknown-fields:'; // unknown-fields:<id> → UnknownFields

export interface SourceSettings {
  ingest?: boolean;
  display?: DisplayMode;
}

export interface UnknownFields {
  fields: string[];
  firstSeen: string; // ISO
  lastSeen: string; // ISO
}

/** KV's bulk `get` takes at most 100 keys. */
const KV_BULK_LIMIT = 100;

const SettingsSchema = z.object({
  ingest: z.boolean().optional(),
  display: z.enum(['full', 'link', 'hidden']).optional(),
});

export function sourceSettingsKey(sourceId: string): string {
  return `${SOURCE_SETTINGS_PREFIX}${sourceId}`;
}

export function unknownFieldsKey(sourceId: string): string {
  return `${UNKNOWN_FIELDS_PREFIX}${sourceId}`;
}

/** Null for a missing, non-JSON or wrongly shaped value. Unknown keys are ignored. */
export function parseSourceSettings(raw: string | null): SourceSettings | null {
  if (raw === null) return null;
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return null;
  }
  const res = SettingsSchema.safeParse(json);
  if (!res.success) return null;
  const out: SourceSettings = {};
  if (res.data.ingest !== undefined) out.ingest = res.data.ingest;
  if (res.data.display !== undefined) out.display = res.data.display;
  return out;
}

/** Bulk KV get, ≤ 100 keys per call. Ids without a valid override are absent from the map. */
export async function readSourceSettings(
  kv: KVNamespace,
  ids: readonly string[],
): Promise<Map<string, SourceSettings>> {
  const out = new Map<string, SourceSettings>();
  for (let i = 0; i < ids.length; i += KV_BULK_LIMIT) {
    const chunk = ids.slice(i, i + KV_BULK_LIMIT);
    const got = await kv.get(chunk.map(sourceSettingsKey), 'text');
    for (const id of chunk) {
      const parsed = parseSourceSettings(got.get(sourceSettingsKey(id)) ?? null);
      if (parsed) out.set(id, parsed);
    }
  }
  return out;
}
