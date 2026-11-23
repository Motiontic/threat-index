import changes from './fixtures/changes.json';
import entries from './fixtures/entries.json';
import type { EntryPreview } from './types';

/** A fixture record: the preview fields plus the registry ids of the sources it cites. */
export interface FixtureEntry extends EntryPreview {
  sources: string[];
}

export const FIXTURE_ENTRIES = entries as FixtureEntry[];
export const FIXTURE_CHANGES = changes as { date: string; key: string; text: string }[];
