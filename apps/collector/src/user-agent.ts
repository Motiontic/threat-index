import type { SourceConfig } from '@ti/sources/registry';
import type { Env } from './env';

const EMAIL = /^[^\s@;()<>]+@[^\s@;()<>]+\.[^\s@;()<>]+$/;
const UA_CONTACT = /;\s*([^\s;()<>]+@[^\s;()<>]+)\s*\)/;

/** True when any URL the source is pulled from is on sec.gov (SEC wants a named sender and a contact). */
export function isSecSource(source: SourceConfig): boolean {
  const urls = [...(source.urls ?? []), JSON.stringify(source.pull ?? {})].join(' ');
  return /https?:\/\/(?:[a-z0-9-]+\.)*sec\.gov(?:[/:?#"]|$)/i.test(urls);
}

/** The contact address: `CONTACT_EMAIL`, else the address inside `USER_AGENT`'s trailing `(…; a@b)`. */
export function contactEmail(env: Pick<Env, 'CONTACT_EMAIL' | 'USER_AGENT'>): string | null {
  const direct = env.CONTACT_EMAIL?.trim();
  if (direct && EMAIL.test(direct)) return direct;
  const m = UA_CONTACT.exec(env.USER_AGENT ?? '');
  return m?.[1] && EMAIL.test(m[1]) ? m[1] : null;
}

/** `Motiontic Threat Index <contact>`, or null when no contact is configured. */
export function secUserAgent(env: Pick<Env, 'CONTACT_EMAIL' | 'USER_AGENT'>): string | null {
  const c = contactEmail(env);
  return c ? `Motiontic Threat Index ${c}` : null;
}
