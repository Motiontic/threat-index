/** SwiftURL follows SwiftPM: SemVer 2.0 precedence, build metadata ignored. */
import type { Comparer } from './index';
import { semver } from './semver';

export const swift: Comparer = semver;
