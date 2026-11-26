# Version-ordering test vectors

Test data for `packages/core/src/versions/`: pairs `a <op> b` (`<`, `=`, `>`), one per line. Blank lines are
skipped, and lines starting `# ` or `// ` are comments. These are lists of version strings, not vulnerability
data, so the NOTICE line "no third-party vulnerability data" stays true and NOTICE is unchanged. Apache-2.0
section 4(d) only requires carrying over an upstream NOTICE file, and neither osv-scalibr nor osv.dev has one
at the pinned commits.

Every vendored line is Apache-2.0, CC BY or public domain. Test lines that upstream marks as taken from a GPL
project were not vendored (see "GPL-marked lines" below).

## osv-scalibr/ (copied from upstream, two files trimmed)

- Source: https://github.com/google/osv-scalibr, `semantic/testdata/`
- Commit: `ce5ed63433445d0fd593efb273a18b87c57f02bc` (25 Nov 2026)
- Licence: Apache-2.0, Copyright Google LLC
- Fetched from `https://raw.githubusercontent.com/google/osv-scalibr/<commit>/semantic/testdata/<file>`.
- `cran-*` and `hackage-*` files are skipped: MTI has no data for those ecosystems.

The blob SHA is `git hash-object` of the file as fetched. All 16 matched the SHAs in the spec when fetched
(output saved with the build proof). The last column says what is in this folder now.

| File | Bytes (upstream) | Blob SHA (upstream) | In this folder |
| ---- | ---------------- | ------------------- | -------------- |
| `alpine-versions-generated.txt` | 301708 | `2172125a79909906344d59fe3185556268f8cc6d` | unchanged |
| `alpine-versions.txt` | 13776 | `53258da2547ee0025bc0d93831fbb666171e6f1e` | trimmed (see below) |
| `debian-versions-generated.txt` | 451277 | `91b2b43f74f9f310e3f90c96332821fc117249cc` | unchanged |
| `debian-versions.txt` | 701 | `1672bcd3cb831192a5a5185a2bda99fa3f9b8548` | unchanged |
| `maven-versions-generated.txt` | 303561 | `3b24fc570e990a7e143761b367f364213fd3198b` | unchanged |
| `maven-versions.txt` | 1848 | `d3d5ff15a41af1563bfa4ca2ca352aa08128e2e4` | unchanged |
| `nuget-versions.txt` | 1060 | `ac940baea3057f634d7c33bcca3412f1ee9d4273` | unchanged |
| `packagist-versions-generated.txt` | 201633 | `8b50879510e492127b1d75cb769ff08301955854` | unchanged |
| `packagist-versions.txt` | 1984 | `dd3f4cb8ecf8b07659d61761fc1df3b75d921b4f` | trimmed (see below) |
| `pub-versions.txt` | 2450 | `cb2143ab88a78f4e93cc31a2e077922b04aae96f` | unchanged |
| `pypi-versions-generated.txt` | 217760 | `2af318c3cdab5af0bf7b461a08dd26b243a5bffc` | unchanged |
| `pypi-versions.txt` | 1280 | `d7d1dd917855127ab8d3d600422712ca70d8a136` | unchanged |
| `redhat-versions.txt` | 2757 | `34d35d44b658e3ca18872a344bd3c9d8055e9a4a` | unchanged |
| `rubygems-versions-generated.txt` | 71880 | `f07e2529a2a6c118801da334d89767031b47ab88` | unchanged |
| `rubygems-versions.txt` | 622 | `78ea3515c1260077f06a1cdf94e57960d2a6ae16` | unchanged |
| `semver-versions.txt` | 2056 | `9ad42ec67393236284aad0ffca7b148a0b1225ef` | unchanged |

Upstream origins that scalibr's own comments name:

- `packagist-versions.txt`: php-src `ext/standard/tests/versioning/version_compare.phpt` and composer/semver
  `tests/ComparatorTest.php`;
- `alpine-versions.txt`: apk-tools `tests/version.data`.

### GPL-marked lines

php-src and apk-tools are under GPL-style licences, so their lines are not vendored here:

- `packagist-versions.txt`: upstream lines 1-92 (the php-src block and the composer/semver block) are
  removed. Kept: upstream lines 93-107, scalibr's own "Edge case tests".
- `alpine-versions.txt`: upstream lines 69-800 (everything after the comment `# from
  https://raw.githubusercontent.com/alpinelinux/apk-tools/master/tests/version.data`) are removed. Kept:
  upstream lines 1-68, scalibr's own cases.

`mti/packagist.txt` and `mti/alpine.txt` hold our own cases for those two comparers, written from the
published version rules. The `*-generated.txt` files are lists of real package versions and are kept.

## osv-dev/ (ported)

- Source: https://github.com/google/osv.dev, `osv/ecosystems/maven_test.py`
- Commit: `d60b14dd943e35d7b790c8649da2804bd9e48a01`
- Licence: Apache-2.0, Copyright Google LLC. The tests are in turn ported from Apache Maven's
  `ComparableVersionTest.java`.
- `maven.txt` is ported from the in-memory ordering tests `test_versions_qualifiers`, `test_versions_number`,
  `test_versions_order`, `test_versions_order_mng_5568`, `test_versions_order_mng_6572` and
  `test_versions_equal`. Each ordered list becomes `a < b` lines for its adjacent pairs, and each equal group
  becomes `a = b` lines. Each block starts with `# from osv/ecosystems/maven_test.py::<test>`.
- Left out: tests that need recorded HTTP, any case with osv.dev's `0` sentinel, and `alpha < 0.0` (from
  `test_versions_order`; `alpha` has no digit, so MTI's Maven `valid()` rejects it).
- osv.dev's other ecosystem tests encode osv.dev conventions MTI does not follow (`0` sorts first; invalid
  sorts last) and are not ported. Its `testdata/packagist_test_cases.txt` was not vendored.

## standards/ (from the published specs)

- `semver-org.txt`: precedence and build-metadata examples from SemVer 2.0.0 sections 10-11
  (https://semver.org/spec/v2.0.0.html). CC BY 3.0, Copyright Tom Preston-Werner. Used with attribution.
- `pep440.txt`: examples from PEP 440 (https://peps.python.org/pep-0440/). Public domain.

## mti/ (written for this repo, Apache-2.0)

Written here where the published files have gaps: `go.txt`, `github-actions.txt`, `nuget.txt`, `maven.txt`,
`dpkg.txt`, `rpm.txt`, `packagist.txt`, `alpine.txt`. The Packagist and Alpine files replace the GPL-marked
lines above, and follow the rules in the comparers' doc comments.
