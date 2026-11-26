/**
 * Go modules: SemVer rules with or without the `v` (Go modules use `v1.2.3`, OSV Go data uses `1.2.3`).
 * `vMAJOR` and `vMAJOR.MINOR` are shorthands for `.0`, and `+incompatible` is build metadata. Pseudo-versions
 * (`v0.0.0-20191109021931-daa7c04131f5`) order as ordinary prereleases, which is how Go orders them.
 * Toolchain names (`go1.21.3`) don't parse, so they are invalid.
 */
import type { Comparer } from './index';
import { semver } from './semver';

export const go: Comparer = semver;
