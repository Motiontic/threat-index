/** crates.io follows Cargo: SemVer 2.0 precedence, build metadata ignored. */
import type { Comparer } from './index';
import { semver } from './semver';

export const crates: Comparer = semver;
