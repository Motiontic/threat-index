import entries from './fixtures/entries.json';

export type FixtureType = 'vuln' | 'breach' | 'ai' | 'mal' | 'tech' | 'term';

/** A fixture record: hand-written public facts plus the registry ids of the sources it cites. */
export interface FixtureEntry {
  key: string;
  type: FixtureType;
  title: string;
  subtitle: string;
  summary: string;
  aliases: string[];
  published: string | null;
  cvss: number | null;
  kev_added: string | null;
  sources: string[];
}

export const FIXTURE_ENTRIES = entries as FixtureEntry[];
