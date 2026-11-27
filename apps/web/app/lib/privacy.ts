import { PRIVACY_SECTIONS, type PrivacySection } from './privacy-content';

/** `[[OWNER: …]]`: a decision only the owner can make. */
export const OWNER_PLACEHOLDER = /\[\[OWNER:[^\]]*\]\]/g;

/** Every placeholder still in the page text. */
export function ownerPlaceholders(sections: PrivacySection[] = PRIVACY_SECTIONS): string[] {
  return sections.flatMap((s) => s.statements.flatMap((st) => st.text.match(OWNER_PLACEHOLDER) ?? []));
}

/** The page may not be served in production while any placeholder remains. */
export function privacyBlocked(
  tiEnv: string | undefined,
  sections: PrivacySection[] = PRIVACY_SECTIONS,
): boolean {
  return tiEnv === 'production' && ownerPlaceholders(sections).length > 0;
}

export type Piece = { text: string; placeholder: boolean };

/** Splits a statement into plain text and placeholders, so the page can highlight the placeholders. */
export function splitPlaceholders(text: string): Piece[] {
  const out: Piece[] = [];
  let last = 0;
  for (const m of text.matchAll(OWNER_PLACEHOLDER)) {
    if (m.index > last) out.push({ text: text.slice(last, m.index), placeholder: false });
    out.push({ text: m[0], placeholder: true });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last), placeholder: false });
  return out;
}
