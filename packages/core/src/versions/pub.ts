/**
 * Pub follows pub_semver: SemVer precedence, but build metadata is ordered. With an equal core and
 * prerelease, a version with no build is lower than one with a build
 * (`1.0.0-pre < 1.0.0-pre+build < 1.0.0 < 1.0.0+build`), and build identifiers compare like prerelease ones.
 */

import { makeComparer } from './common';
import type { Comparer } from './index';
import { compareSemverParts, parseSemver } from './semver';

export const pub: Comparer = makeComparer(parseSemver, (a, b) => compareSemverParts(a, b, true));
