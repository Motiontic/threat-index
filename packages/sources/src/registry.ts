import type { LicenceStatus } from '@ti/core/licence';
import aiaaic from './sources/aiaaic';
import aiid from './sources/aiid';
import avid from './sources/avid';
import bsiCertBund from './sources/bsi-cert-bund';
import caAg from './sources/ca-ag';
import capec from './sources/capec';
import certCc from './sources/cert-cc';
import certFr from './sources/cert-fr';
import certIn from './sources/cert-in';
import cfrTracker from './sources/cfr-tracker';
import cisaAdvisories from './sources/cisa-advisories';
import cisaKev from './sources/cisa-kev';
import cisaVulnrichment from './sources/cisa-vulnrichment';
import cisco from './sources/cisco';
import cpeDictionary from './sources/cpe-dictionary';
import csis from './sources/csis';
import cveList from './sources/cve-list';
import cwe from './sources/cwe';
import databreachesNet from './sources/databreaches-net';
import debian from './sources/debian';
import enisa from './sources/enisa';
import epss from './sources/epss';
import eurepoc from './sources/eurepoc';
import exploitDb from './sources/exploit-db';
import gcve from './sources/gcve';
import githubAdvisoryDb from './sources/github-advisory-db';
import hhsOcr from './sources/hhs-ocr';
import hibp from './sources/hibp';
import jvn from './sources/jvn';
import malpedia from './sources/malpedia';
import metasploit from './sources/metasploit';
import mitAiRisk from './sources/mit-ai-risk';
import mitreAtlas from './sources/mitre-atlas';
import mitreAttack from './sources/mitre-attack';
import msrc from './sources/msrc';
import nucleiTemplates from './sources/nuclei-templates';
import nvd from './sources/nvd';
import openssfMaliciousPackages from './sources/openssf-malicious-packages';
import oracle from './sources/oracle';
import osv from './sources/osv';
import pocInGithub from './sources/poc-in-github';
import projectZero from './sources/project-zero';
import ransomwareLive from './sources/ransomware-live';
import redHat from './sources/red-hat';
import secEdgar from './sources/sec-edgar';
import shadowserver from './sources/shadowserver';
import stateAgs from './sources/state-ags';
import trickestCve from './sources/trickest-cve';
import ubuntu from './sources/ubuntu';
import ukIco from './sources/uk-ico';
import umdCissm from './sources/umd-cissm';
import vcdb from './sources/vcdb';
import vulncheck from './sources/vulncheck';
import waAg from './sources/wa-ag';
import zdi from './sources/zdi';

/**
 * The 55 sources, one file each in ./sources/<id>.ts (default export). To work on one source, edit
 * only its file. Licence statuses reflect our review on 22 Nov 2026 (not legal advice).
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
  /** Where the source is fetched from. Filled per source by later work. */
  urls?: string[];
  /** Name of the parser module in @ti/parsers (`@ti/parsers/<name>`). */
  parser?: string;
  rateLimit?: { perMinute: number };
}

// The `src()` helper lives in ./define so source files can use it without an import cycle.
export { src } from './define';

export const SOURCES: readonly SourceConfig[] = [
  // Free, licence allows commercial use (24)
  cveList,
  cisaVulnrichment,
  githubAdvisoryDb,
  osv,
  cwe,
  capec,
  cpeDictionary,
  nvd,
  redHat,
  cisaKev,
  metasploit,
  nucleiTemplates,
  pocInGithub,
  trickestCve,
  mitreAttack,
  mitreAtlas,
  openssfMaliciousPackages,
  mitAiRisk,
  avid,
  secEdgar,
  hhsOcr,
  hibp,
  cisaAdvisories,
  ukIco,
  // Need written permission: off (`wait`) or link-only (`link`) until it arrives (8)
  vulncheck,
  certFr,
  zdi,
  malpedia,
  aiid,
  ransomwareLive,
  eurepoc,
  databreachesNet,
  // No written terms found: on and credited, written confirmation sought (23)
  enisa,
  gcve,
  msrc,
  cisco,
  oracle,
  debian,
  ubuntu,
  certCc,
  jvn,
  bsiCertBund,
  certIn,
  epss,
  exploitDb,
  projectZero,
  shadowserver,
  aiaaic,
  caAg,
  waAg,
  stateAgs,
  vcdb,
  cfrTracker,
  csis,
  umdCissm,
];

export const SOURCE_BY_ID: ReadonlyMap<string, SourceConfig> = new Map(SOURCES.map((s) => [s.id, s]));
