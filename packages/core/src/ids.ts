const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const GHSA_RE = /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/i;

/** Canonical form for IDs we compare across sources. */
export function normaliseId(raw: string): string {
  const id = raw.trim();
  if (CVE_RE.test(id)) return id.toUpperCase();
  if (GHSA_RE.test(id)) return `GHSA${id.slice(4).toLowerCase()}`;
  return id;
}

export function isCve(id: string): boolean {
  return CVE_RE.test(id.trim());
}

/** The hub key for a flaw: its CVE if any alias has one, otherwise its own ID. */
export function vulnKeyFor(id: string, aliases: readonly string[] = []): string {
  const all = [id, ...aliases].map(normaliseId);
  return all.find(isCve) ?? normaliseId(id);
}
