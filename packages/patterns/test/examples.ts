import type { PullConfig } from '@ti/sources/pull';
import { SOURCE_BY_ID, type SourceConfig } from '@ti/sources/registry';

/** One `pull` block per worked example. Each source's parser feature later copies its block over. */
export const EXAMPLES = {
  'cve-list': {
    git: { repo: 'CVEProject/cvelistV5', branch: 'main', include: ['cves/**/*.json'] },
  },
  osv: {
    changelist: {
      listUrl: 'https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv',
      timeColumn: 0,
      refColumn: 1,
      itemUrl: 'https://osv-vulnerabilities.storage.googleapis.com/{ref}.json',
    },
  },
  nvd: {
    since: {
      url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      startParam: 'lastModStartDate',
      endParam: 'lastModEndDate',
      offsetParam: 'startIndex',
      limitParam: 'resultsPerPage',
      itemsPath: 'vulnerabilities',
      idPath: 'cve.id',
      totalPath: 'totalResults',
      maxWindowDays: 120,
      auth: { header: 'apiKey', credential: 'nvd' },
    },
  },
  'cisa-kev': {
    fingerprint: {
      url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      format: 'json',
      itemsPath: 'vulnerabilities',
      key: 'cveID',
      version: { bytes: 512, pattern: '"catalogVersion"\\s*:\\s*"([^"]+)"' },
    },
  },
  'cisa-advisories': {
    feed: { url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml' },
  },
  'cert-in': {
    page: {
      url: 'https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01',
      item: 'tr.advisory',
      key: 'id',
      fields: {
        id: 'td.id',
        title: 'td.title a',
        date: 'td.date',
        link: { selector: 'td.title a', attr: 'href' },
      },
    },
  },
  cwe: {
    heavy: {
      url: 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
      version: { url: 'https://cwe.mitre.org/data/downloads.html', pattern: 'Version ([\\d.]+)' },
    },
  },
} satisfies Record<string, PullConfig>;

export type ExampleId = keyof typeof EXAMPLES;

/** The registered source with its worked-example `pull` block. */
export function sourceWith(id: ExampleId, extra: Partial<SourceConfig> = {}): SourceConfig {
  const base = SOURCE_BY_ID.get(id);
  if (!base) throw new Error(`no source ${id}`);
  return { ...base, pull: EXAMPLES[id], ...extra };
}
