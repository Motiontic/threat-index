import { siteOrigin } from './config';
import type { Env } from './env';

const PART = /^[A-Za-z0-9._:@+-]{1,128}$/;

/** A link to an MTI page, built from checked parts. Null when a part fails its pattern. */
export function mtiLink(
  env: Pick<Env, 'MCP_RESOURCE_URL'>,
  page: 'entry' | 'breach' | 'incident' | 'technique' | 'sources',
  ...parts: string[]
): string | null {
  if (parts.some((p) => !PART.test(p) || p.includes('..') || p === '.')) return null;
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

const SEG = '[A-Za-z0-9._~%+:@-]{1,128}';
const GHSA_PATH = /^\/advisories\/GHSA(-[23456789cfghjmpqrvwx]{4}){3}\/?$/i;
/** Path shape per host. A host without a known shape gets no link. */
const HOST_PATHS: Record<string, RegExp> = {
  'nvd.nist.gov': /^\/vuln\/detail\/CVE-\d{4}-\d{4,7}$/i,
  'www.cve.org': /^\/CVERecord$/,
  'www.cisa.gov': new RegExp(
    `^/(?:news-events|resources-tools|known-exploited-vulnerabilities-catalog)(?:/${SEG}){0,8}$`,
  ),
  'osv.dev': new RegExp(`^/vulnerability/${SEG}$`),
  'euvd.enisa.europa.eu': new RegExp(`^/vulnerability/${SEG}$`),
  'access.redhat.com': new RegExp(`^/(?:errata|security/cve|security/vulnerabilities)/${SEG}$`),
  'ubuntu.com': new RegExp(`^/security/(?:notices|CVE-\\d{4}-\\d{4,7})(?:/${SEG})?$`),
  'security-tracker.debian.org': new RegExp(`^/tracker/${SEG}$`),
  'jvndb.jvn.jp': new RegExp(`^/(?:en/)?contents/\\d{4}/${SEG}$`),
  'kb.cert.org': /^\/vuls\/id\/\d{1,10}$/,
  'attack.mitre.org': new RegExp(`^/(?:techniques|software|groups)/${SEG}(?:/\\d{3})?$`),
  'atlas.mitre.org': new RegExp(`^/techniques/${SEG}$`),
  'cwe.mitre.org': /^\/data\/definitions\/\d{1,6}\.html$/,
  'capec.mitre.org': /^\/data\/definitions\/\d{1,6}\.html$/,
  'www.sec.gov': new RegExp(`^/(?:Archives|cgi-bin)(?:/${SEG}){1,6}$`),
};
const BAD_PATH_CHARS = /[()[\]<>!'"\\\s]/;

/**
 * An outside link we are willing to pass on. Scheme, host and path only: https, an allow-listed host, no user
 * info, port or IP literal, a path of a known shape, and no query or fragment.
 */
export function sourceLink(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length > 2048) return null;
  // The URL parser turns `\` into `/`, so look for it before parsing.
  if (raw.includes('\\')) return null;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username || u.password || u.port) return null;
  const host = u.hostname;
  if (host.startsWith('[') || /^\d+(\.\d+){3}$/.test(host)) return null;
  // Inspect the path as sent, so encoded forms of a bad character are refused too.
  let decoded: string;
  try {
    decoded = decodeURIComponent(u.pathname);
  } catch {
    return null;
  }
  for (const p of [u.pathname, decoded]) {
    if (
      BAD_PATH_CHARS.test(p) ||
      p.includes('//') ||
      p.split('/').includes('..') ||
      p.split('/').includes('.')
    )
      return null;
  }
  // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing controls is the point
  if (/[\u0000-\u001f\u007f-\u009f]/.test(decoded)) return null;
  const shape = host === 'github.com' ? GHSA_PATH : HOST_PATHS[host];
  if (!shape || (!SOURCE_LINK_HOSTS.has(host) && host !== 'github.com')) return null;
  if (!shape.test(u.pathname)) return null;
  const out = `https://${host}${u.pathname}`;
  return out.length <= 300 ? out : null;
}
