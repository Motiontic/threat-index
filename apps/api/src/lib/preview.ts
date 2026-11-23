/** Fields a visitor may see. Everything else needs a free account. */
export const PREVIEW_FIELDS = ['key', 'kind', 'title', 'summary', 'published', 'cvss', 'kev_added'] as const;

export function previewEntry(row: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(PREVIEW_FIELDS.map((f) => [f, row[f] ?? null]));
}
