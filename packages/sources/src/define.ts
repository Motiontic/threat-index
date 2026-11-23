import type { LicenceStatus } from '@ti/core/licence';
import type { Cadence, PatternName, SourceConfig } from './registry';

/** Builds a SourceConfig. The default credit is "Source: <name>". */
export const src = (
  id: string,
  name: string,
  gives: string,
  pattern: PatternName,
  cadence: Cadence,
  licence: LicenceStatus,
  extra: Partial<SourceConfig> = {},
): SourceConfig => ({ id, name, gives, pattern, cadence, licence, credit: `Source: ${name}`, ...extra });
