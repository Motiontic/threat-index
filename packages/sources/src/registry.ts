import type { LicenceStatus } from '@ti/core';
import { NVD_NOTICE } from '@ti/core';

/**
 * The 55 sources. Licence statuses reflect our review on 22 Nov 2026 (not legal advice).
 * `wait` = off until written permission; `link` = ID, title, date and link only.
 * KV (`SETTINGS`) can override `ingest` and `display` per source without a redeploy.
 */
export type PatternName = 'git' | 'changelist' | 'since' | 'fingerprint' | 'feed' | 'page' | 'heavy';
export type Cadence = '3h' | 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'with-cve-list';

export interface SourceConfig {
  id: string;
  name: string;
  gives: string;
  pattern: PatternName;
  cadence: Cadence;
  licence: LicenceStatus;
  credit: string;
  /** Hand big files to E2B instead of parsing in a Worker. */
  heavy?: boolean;
}

const src = (
  id: string,
  name: string,
  gives: string,
  pattern: PatternName,
  cadence: Cadence,
  licence: LicenceStatus,
  extra: Partial<SourceConfig> = {},
): SourceConfig => ({ id, name, gives, pattern, cadence, licence, credit: `Source: ${name}`, ...extra });

export const SOURCES: readonly SourceConfig[] = [
  // Free, licence allows commercial use (24)
  src('cve-list', 'CVE List', 'Every CVE record', 'git', '3h', 'on', {
    credit: 'Source: CVE Program (cve.org)',
  }),
  src(
    'cisa-vulnrichment',
    'CISA Vulnrichment',
    "CISA's exploitation calls, CVSS, CWE",
    'git',
    'with-cve-list',
    'on',
  ),
  src(
    'github-advisory-db',
    'GitHub Advisory DB',
    'Package advisories and malware alerts',
    'git',
    '3h',
    'on',
    { credit: 'Source: GitHub Advisory Database (CC BY 4.0)' },
  ),
  src('osv', 'OSV.dev', 'Affected package versions', 'changelist', '3h', 'on'),
  src('cwe', 'CWE', 'Weakness types', 'heavy', 'weekly', 'on', {
    heavy: true,
    credit: 'Source: CWE™ (MITRE)',
  }),
  src('capec', 'CAPEC', 'Attack patterns', 'heavy', 'weekly', 'on', {
    heavy: true,
    credit: 'Source: CAPEC™ (MITRE)',
  }),
  src('cpe-dictionary', 'CPE dictionary', 'Product names', 'since', 'daily', 'on', { credit: NVD_NOTICE }),
  src('nvd', 'NVD', 'CVSS scores and affected products', 'since', '3h', 'on', { credit: NVD_NOTICE }),
  src('red-hat', 'Red Hat', 'Red Hat fix status', 'changelist', '3h', 'on', {
    credit: 'Source: Red Hat Security Data (CC BY 4.0)',
  }),
  src('cisa-kev', 'CISA KEV', 'Exploited in the wild', 'fingerprint', '3h', 'on'),
  src('metasploit', 'Metasploit', 'Weaponised exploit exists', 'git', '3h', 'on'),
  src('nuclei-templates', 'Nuclei templates', 'A scanner can detect it', 'git', '3h', 'on'),
  src('poc-in-github', 'PoC-in-GitHub', 'Proof-of-concept repos (weak signal)', 'git', '3h', 'on'),
  src('trickest-cve', 'trickest/cve', 'Proof-of-concept links (weak signal)', 'git', 'daily', 'on'),
  src('mitre-attack', 'MITRE ATT&CK', 'Attacker techniques', 'heavy', 'weekly', 'on', {
    heavy: true,
    credit: 'Source: MITRE ATT&CK®',
  }),
  src('mitre-atlas', 'MITRE ATLAS', 'AI attack techniques', 'heavy', 'weekly', 'on', {
    heavy: true,
    credit: 'Source: MITRE ATLAS™',
  }),
  src('openssf-malicious-packages', 'OpenSSF malicious packages', 'Poisoned packages', 'git', '3h', 'on'),
  src('mit-ai-risk', 'MIT AI Risk Repository', 'AI risk categories', 'heavy', 'monthly', 'on', {
    heavy: true,
  }),
  src('avid', 'AVID', 'AI vulnerability reports', 'git', 'weekly', 'on'),
  src('sec-edgar', 'SEC EDGAR', '8-K Item 1.05 cyber incidents', 'feed', '3h', 'on'),
  src('hhs-ocr', 'HHS OCR', 'US health breaches', 'fingerprint', 'daily', 'on'),
  src('hibp', 'Have I Been Pwned', 'Verified breached datasets', 'fingerprint', '3h', 'on', {
    credit: 'Source: Have I Been Pwned (haveibeenpwned.com, CC BY 4.0)',
  }),
  src('cisa-advisories', 'CISA advisories', 'Government alerts', 'feed', '3h', 'on'),
  src('uk-ico', 'UK ICO', 'UK incident statistics', 'heavy', 'quarterly', 'on', {
    heavy: true,
    credit: 'Source: UK ICO (Open Government Licence v3.0)',
  }),

  // Need written permission: off (`wait`) or link-only (`link`) until it arrives (8)
  src('vulncheck', 'VulnCheck', 'Wider exploited list with evidence', 'since', '3h', 'wait', {
    credit: 'Source: VulnCheck KEV',
  }),
  src('cert-fr', 'CERT-FR', 'French government advisories', 'feed', 'daily', 'wait'),
  src('zdi', 'Zero Day Initiative', 'Vulnerability disclosures', 'feed', '3h', 'link'),
  src('malpedia', 'Malpedia', 'Malware families', 'fingerprint', 'daily', 'wait'),
  src('aiid', 'AI Incident Database', 'AI incidents', 'heavy', 'weekly', 'wait', { heavy: true }),
  src('ransomware-live', 'ransomware.live', 'Ransomware victims', 'since', '3h', 'wait', {
    credit: 'Source: Ransomware.live',
  }),
  src('eurepoc', 'EuRepoC', 'State-linked incidents', 'heavy', 'monthly', 'wait', { heavy: true }),
  src('databreaches-net', 'DataBreaches.net', 'Breach news leads', 'feed', '3h', 'link'),

  // No written terms found: on and credited, written confirmation sought (23)
  src('enisa', 'ENISA (EUVD + EU KEV)', 'EU IDs and EU exploited list', 'since', '3h', 'ask'),
  src('gcve', 'GCVE', 'Cross-ID links', 'since', 'daily', 'ask'),
  src('msrc', 'Microsoft MSRC', 'Patch Tuesday fixes', 'changelist', 'daily', 'ask'),
  src('cisco', 'Cisco', 'Cisco advisories', 'changelist', '3h', 'ask'),
  src('oracle', 'Oracle', 'Quarterly patches', 'changelist', 'daily', 'ask'),
  src('debian', 'Debian', 'Debian fix status (through OSV)', 'changelist', '3h', 'ask'),
  src('ubuntu', 'Ubuntu', 'Ubuntu fix status (through OSV)', 'changelist', '3h', 'ask'),
  src('cert-cc', 'CERT/CC', 'Vendor affected or not', 'since', 'daily', 'ask'),
  src('jvn', 'JVN', 'Japanese vendor advisories', 'feed', 'daily', 'ask'),
  src('bsi-cert-bund', 'BSI CERT-Bund', 'German advisories', 'changelist', '3h', 'ask'),
  src('cert-in', 'CERT-In', 'Indian government advisories', 'page', 'daily', 'ask'),
  src('epss', 'EPSS', 'Daily chance of exploitation', 'since', 'daily', 'ask', {
    heavy: true,
    credit: 'Source: EPSS (FIRST)',
  }),
  src('exploit-db', 'Exploit-DB', 'Public exploit exists', 'git', '3h', 'ask'),
  src('project-zero', 'Project Zero 0-day sheet', 'Zero-days exploited', 'fingerprint', 'weekly', 'ask'),
  src('shadowserver', 'Shadowserver', 'Exposure statistics', 'since', 'daily', 'ask'),
  src('aiaaic', 'AIAAIC', 'AI incidents and controversies', 'heavy', 'weekly', 'ask', { heavy: true }),
  src('ca-ag', 'California AG', 'Breach notices', 'fingerprint', 'daily', 'ask'),
  src('wa-ag', 'Washington AG', 'Breach notices', 'since', 'daily', 'ask'),
  src('state-ags', 'Other state AG portals', 'Breach notices, ~19 states', 'page', 'daily', 'ask'),
  src('vcdb', 'VCDB (VERIS)', 'Coded breach incidents', 'git', 'daily', 'ask'),
  src('cfr-tracker', 'CFR Cyber Operations Tracker', 'State-sponsored operations', 'page', 'weekly', 'ask'),
  src('csis', 'CSIS significant incidents', 'Major incidents timeline', 'heavy', 'monthly', 'ask', {
    heavy: true,
  }),
  src('umd-cissm', 'UMD CISSM', 'Cyber events database', 'heavy', 'monthly', 'ask', { heavy: true }),
];

export const SOURCE_BY_ID: ReadonlyMap<string, SourceConfig> = new Map(SOURCES.map((s) => [s.id, s]));
