import { truncate } from './format';

export const SITE_NAME = 'Threat Index';

export interface PageMeta {
  title: string;
  description: string;
  /** Path and query of the canonical URL, e.g. `/e/CVE-2025-3248`. */
  path: string;
  origin: string;
  noindex?: boolean;
}

type MetaDescriptor = Record<string, string>;

export function buildMeta(page: PageMeta): MetaDescriptor[] {
  const description = truncate(page.description, 160);
  const url = new URL(page.path, page.origin).toString();
  const tags: MetaDescriptor[] = [
    { title: page.title },
    { name: 'description', content: description },
    { property: 'og:title', content: page.title },
    { property: 'og:description', content: description },
    { property: 'og:type', content: 'website' },
    { property: 'og:url', content: url },
    { tagName: 'link', rel: 'canonical', href: url },
  ];
  if (page.noindex) tags.push({ name: 'robots', content: 'noindex' });
  return tags;
}

/** `title · Threat Index` */
export function pageTitle(title: string): string {
  return `${title} · ${SITE_NAME}`;
}

/** Escapes characters that could end a script element or break a JS string, inside JSON. */
export function escapeJsonLd(json: string): string {
  return json
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

export function jsonLdString(data: Record<string, unknown>): string {
  return escapeJsonLd(JSON.stringify(data));
}

/** The app's only `dangerouslySetInnerHTML`. The payload is JSON with `<`, `>` and `&` escaped. */
export function JsonLd({ data, nonce }: { data: Record<string, unknown>; nonce?: string }) {
  return (
    <script
      type="application/ld+json"
      nonce={nonce}
      // biome-ignore lint/security/noDangerouslySetInnerHtml: escaped JSON-LD, see escapeJsonLd
      dangerouslySetInnerHTML={{ __html: jsonLdString(data) }}
    />
  );
}
