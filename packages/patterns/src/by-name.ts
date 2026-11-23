import type { PatternName } from '@ti/sources/registry';
import * as changelist from './changelist';
import * as feed from './feed';
import * as fingerprint from './fingerprint';
import * as git from './git';
import * as heavy from './heavy';
import * as page from './page';
import * as since from './since';
import type { PatternContext, PatternResult } from './types';

export interface PatternModule {
  check(ctx: PatternContext): Promise<'unchanged' | 'changed'>;
  fetch(ctx: PatternContext): Promise<PatternResult>;
}

const MODULES: Record<PatternName, PatternModule> = {
  changelist,
  feed,
  fingerprint,
  git,
  heavy,
  page,
  since,
};

/** The module (`{ check, fetch }`) behind a source's pattern name. */
export function patternFor(name: PatternName): PatternModule {
  return MODULES[name];
}
