import { siteOrigin } from './config';
import type { Env } from './env';

const PART = /^[A-Za-z0-9._:@+-]{1,128}$/;

/** A link to an MTI page, built from checked parts. Null when a part fails its pattern. */
export function mtiLink(
  env: Pick<Env, 'MCP_RESOURCE_URL'>,
  page: 'entry' | 'breach' | 'incident' | 'technique' | 'sources',
  ...parts: string[]
): string | null {
  if (parts.some((p) => !PART.test(p))) return null;
  const base = siteOrigin(env);
  const enc = parts.map(encodeURIComponent);
  switch (page) {
    case 'entry':
      return enc.length === 1 ? `${base}/e/${enc[0]}` : null;
    case 'breach':
      return enc.length === 1 ? `${base}/breach/${enc[0]}` : null;
    case 'incident':
      return enc.length === 2 ? `${base}/incident/${enc[0]}/${enc[1]}` : null;
    case 'technique':
      return enc.length === 1 ? `${base}/technique/${enc[0]}` : null;
    case 'sources':
      return enc.length === 0 ? `${base}/sources` : null;
  }
}

export const SOURCE_LINK_HOSTS: ReadonlySet<string> = new Set([
  'nvd.nist.gov',
  'www.cve.org',
  'www.cisa.gov',
  'osv.dev',
  'euvd.enisa.europa.eu',
  'access.redhat.com',
  'ubuntu.com',
  'security-tracker.debian.org',
  'jvndb.jvn.jp',
  'kb.cert.org',
  'attack.mitre.org',
  'atlas.mitre.org',
  'cwe.mitre.org',
  'capec.mitre.org',
  'www.sec.gov',
]);

/** An outside link we are willing to pass on: https, an allow-listed host, no user info, port or IP literal. */
export function sourceLink(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length > 2048) return null;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username || u.password || u.port) return null;
  if (u.hostname.startsWith('[') || /^\d+(\.\d+){3}$/.test(u.hostname)) return null;
  const host = u.hostname;
  if (host === 'github.com') {
    return /^\/advisories\/GHSA(-[23456789cfghjmpqrvwx]{4}){3}\/?$/i.test(u.pathname) ? u.href : null;
  }
  return SOURCE_LINK_HOSTS.has(host) ? u.href : null;
}
