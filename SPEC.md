# parsers-certs: CERT/CC, JVN and BSI CERT-Bund parsers and pull config; CERT-In left unwired

## Why

National CERTs say which CVEs they have written up, when, and where to read it. Four are registered (`cert-cc`,
`jvn`, `bsi-cert-bund`, `cert-in`), but none has a `parser` or a `pull` block, so the collector skips them with
"source has no pull config yet". This change adds three parsers and the pull config for three of them. CERT-In has
no stable machine-readable list, so it stays unwired with a note.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `packages/sources/src/sources/cert-cc.ts` | `since`, `daily`, `ask`; no `parser`, no `pull` |
| `jvn.ts` | `feed`, `daily`, `ask`; no `parser`, no `pull` |
| `bsi-cert-bund.ts` | `changelist`, `3h`, `ask`; no `parser`, no `pull` |
| `cert-in.ts` | `page`, `daily`, `ask`; used as the worked `page` example in `packages/patterns/test/` (those tests set their own `pull`) |
| `packages/parsers/src/csaf.ts`, `feed.ts` | Stubs that throw `NotImplementedError`. Don't edit them; another change may fill `csaf.ts` |
| `loadParser(name)` | Imports `./<name>.ts`; the module must export `parse(input)` returning `ParsedRecord[]` or `ParseResult` |
| Parser input | `feed` pattern: one entry as parsed by `fast-xml-parser` (`ignoreAttributes: false`, prefix `@_`, entities decoded, text next to attributes in `#text`). `changelist`: `ChangeItem { ref, time, text: string \| null }`. `heavy` + `jobKind: 'first-load'`: the E2B job downloads `pull.heavy.url` and passes the whole body as a string (parsed JSON when the URL ends `.json` or the type says JSON) |
| `AdvisoryRecord` | `{ source, sourceId, vulnKey, status, published?, modified, url?, affected? }`. No title or text fields |
| Linker ids | `vulnId()` keeps only `/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/`; a record whose `sourceId` fails is dropped. So `VU#604762` and `JVN#29068051` cannot be ids |
| Limits | `docs/IMPLEMENTATION_PLAN.md`: anything over about 1 MB goes to E2B; `MAX_BODY_BYTES` is 5 MB |

Endpoints, checked on 24 Nov 2026:

- CERT/CC Atom feed `https://kb.cert.org/vuls/atomfeed/`: 200, `application/atom+xml`, ~190 KB, the 15 newest notes
  by first publication, `Last-Modified`, no ETag. Each `<entry>` has `title`, `link`, `published`, `updated` (six
  fraction digits, `+00:00`), `id` (`https://kb.cert.org/vuls/id/<n>`), `summary` and `content` (both escaped HTML).
  The `content` ends with the note's "CVE IDs" block: one `<a href="http://web.nvd.nist.gov/view/vuln/detail?vulnId=YYYY-NNNN">`
  per CVE. That block matched the note API's `cveids` exactly for every note checked; a regex over the whole text
  did not (it also catches CVEs that a note only mentions, for example related bugs in other libraries).
- CERT/CC note API `https://kb.cert.org/vuls/api/<n>/`: JSON with `vuid`, `idnumber`, `name`, `cveids`,
  `datefirstpublished`, `publicdate`, `dateupdated`, `revision` and ~55 mostly null fields. Not wired here.
- JVN iPedia `https://jvndb.jvn.jp/en/rss/jvndb.rdf` ("Update Entry"): 200, `application/rdf+xml`, ~1.4 MB, 500
  `<item>`s, ETag and Last-Modified. Each item: `title`, `link`, `description`, `sec:identifier` (`JVNDB-YYYY-NNNNNN`),
  `sec:references` (`source="CVE" id="CVE-…"`, also JVN and CWE ones), `sec:cpe`, `sec:cvss`, `dc:date`,
  `dcterms:issued`, `dcterms:modified` (times like `2026-11-19T15:40+09:00`, no seconds). Most items list 1–4 CVEs;
  a few roll-ups list hundreds (one had 647). The MyJVN API (`/myjvn?method=getVulnOverviewList…`) answered 404.
- BSI CERT-Bund CSAF provider `https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json`: 200, trusted
  provider. TLP:WHITE directory `https://wid.cert-bund.de/.well-known/csaf/white/`: `changes.csv` (~880 KB, ETag,
  `Accept-Ranges: bytes`, 206 to a range request, 14,908 lines, newest first, lines
  `"2026/wid-sec-w-2026-4715.json","2026-11-22T23:00:00+0000"`). Many lines share one timestamp (364 on one day).
  Documents are ~5–50 KB CSAF 2.0: `document.tracking.id` `WID-SEC-W-2026-4715`, `initial_release_date`,
  `current_release_date`, `document.distribution.tlp.label` `WHITE`, `vulnerabilities[].cve`, and a
  `document.references[]` entry `https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4715`.
- CERT-In `https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01`: 200 but the body says "Page Requested
  Currently Not available"; the lists are reached through JavaScript form posts. No RSS or JSON list was found.

## What to build

Touch only: `packages/parsers/src/{cert-common,cert-cc,jvn,cert-bund}.ts`, new tests under `packages/parsers/test/`,
new `fixtures/{cert-cc,jvn,bsi-cert-bund}/` files, and `packages/sources/src/sources/{cert-cc,jvn,bsi-cert-bund,cert-in}.ts`.
Keep `fixtures/cert-in/` as it is. No other source files, no shared contract files, no migrations, no new
dependencies, no Node-only imports (`node:*`) under `packages/parsers/src`: the code runs in Workers and E2B.

### 1. `packages/parsers/src/cert-common.ts` (helpers, no `parse`)

```ts
export const MAX_CVES_PER_ADVISORY = 1000;
/** ISO 8601 with or without seconds, any fraction, `Z`, `±hh:mm` or `±hhmm` → `YYYY-MM-DDTHH:MM:SS.sssZ`; else null. */
export function isoMs(raw: unknown): string | null;
/** Normalised, unique (first seen wins), valid CVE ids; at most MAX_CVES_PER_ADVISORY. */
export function cveList(raw: readonly unknown[]): string[];
/** One AdvisoryRecord per CVE (`sourceId` `<baseId>:<CVE>`), or one with `vulnKey: null` and `sourceId` `<baseId>`. */
export function perCve(baseId: string, cves: readonly string[],
  fields: Omit<AdvisoryRecord, 'sourceId' | 'vulnKey'>): AdvisoryRecord[];
```

`isoMs` checks the calendar date (no 31 Feb) and truncates the fraction to milliseconds. `perCve` throws when
`baseId` or any produced `sourceId` fails the linker's id rule (above); callers build safe ids first.

### 2. `packages/parsers/src/cert-cc.ts`

Exports `parseCertCcEntry(entry)`, `parseCertCcNote(note)` and `parse(input)` (routes an object with `vuid` or
`idnumber`, or a JSON string of one, to `parseCertCcNote`; anything else to `parseCertCcEntry`). All return
`ParseResult<AdvisoryRecord>`.

- **Note number** from the entry's `id` text, else its `link` `@_href`: must match
  `^https://kb\.cert\.org/vuls/id/(\d{1,7})/?$`; otherwise throw. For a note: `idnumber` (digits only). Base id
  `VU-<n>` (the `#` of `VU#<n>` fails the linker's id rule).
- **CVEs (entry)**: from the text of `content` (string or `#text`), every `vulnId=(\d{4}-\d{4,})` inside an `href`
  to `web.nvd.nist.gov/view/vuln/detail`, prefixed `CVE-`. Never from free text. **(note)**: `cveids`.
- `published`: entry `published` / note `datefirstpublished` then `publicdate`; `modified`: entry `updated` / note
  `dateupdated`, falling back to `published`. No valid `modified` → throw.
- `status: 'active'`; `url`: `https://kb.cert.org/vuls/id/<n>`; `source: 'cert-cc'`.
- Unknown fields: entry keys outside `title`, `link`, `published`, `updated`, `id`, `summary`, `content`, `author`,
  `category`; note keys outside the key set of `fixtures/cert-cc/note-604762.json`, written as `CERT_CC_NOTE_KEYS`.

### 3. `packages/parsers/src/jvn.ts`

`parse(input)` takes the whole RDF document as a string (the first-load job's input) and returns
`ParseResult<AdvisoryRecord>`. No XML library: a small scanner like the one in `cwe.ts`. A body without
`<rdf:RDF` throws; a `<!DOCTYPE` or `<!ENTITY` anywhere throws.

- Walk each `<item …>…</item>`. Read `sec:identifier` (must match `^JVNDB-\d{4}-\d{6}$`; otherwise skip the item
  and add `item.sec:identifier` to `unknownFields` once), the `id` attribute of each `<sec:references source="CVE" …>`,
  `link`, `dcterms:issued`, `dcterms:modified` (fallback `dc:date`). Decode only `&amp; &lt; &gt; &quot; &apos;` and
  numeric references in the values read.
- Records via `perCve(identifier, cves, …)`: `source: 'jvn'`, `status: 'active'`, `published` = issued,
  `modified` = modified (an item with neither is skipped and reported as `item.dcterms:modified`), `url` = `link`
  when it starts `https://jvndb.jvn.jp/`, else `https://jvndb.jvn.jp/en/contents/<yyyy>/<identifier>.html`.
- Unknown fields: child element names of an item outside `title`, `link`, `description`, `sec:identifier`,
  `sec:references`, `sec:cpe`, `sec:cvss`, `dc:date`, `dcterms:issued`, `dcterms:modified`, as `item.<name>`, once each.

### 4. `packages/parsers/src/cert-bund.ts`

A minimal CSAF 2.0 reader for BSI only (`csaf.ts` stays untouched; a later change may fold this into a shared CSAF
parser). `parse(input)` accepts a `ChangeItem`, a JSON string or a parsed object; `text: null` → no records.

- Bad JSON, a non-object, a `document.tracking.id` not matching `^WID-SEC-W-\d{4}-\d{1,6}$` or no valid
  `current_release_date` throws.
- `document.distribution.tlp.label` present and not `WHITE` or `CLEAR` → no records, `unknownFields: ['tlp']`.
  `document.tracking.status` `draft` → no records.
- Records via `perCve(tracking.id, cveList(vulnerabilities[].cve), …)`: `source: 'bsi-cert-bund'`, `published` =
  `initial_release_date`, `modified` = `current_release_date`, `status` `'withdrawn'` when `document.category` is
  `csaf_withdrawn`, else `'active'`; `url` = the first `document.references[].url` starting
  `https://wid.cert-bund.de/portal/`, else none.
- Unknown fields: top-level keys outside `document`, `product_tree`, `vulnerabilities`; `document` keys outside the
  CSAF 2.0 set (`acknowledgments`, `aggregate_severity`, `category`, `csaf_version`, `distribution`, `lang`,
  `notes`, `publisher`, `references`, `source_lang`, `title`, `tracking`) as `document.<key>`. Never read `notes`
  or `product_tree`.

### 5. Source config (only `parser`, `pull`, and where stated `pattern`/`heavy`; never the licence)

| Source | Change |
| ------ | ------ |
| `cert-cc` | `pattern` `since` → `feed` (the API has no modified-since or offset query); `parser: 'cert-cc'`; `pull: { feed: { url: 'https://kb.cert.org/vuls/atomfeed/' } }` |
| `jvn` | `pattern` `feed` → `heavy`, `heavy: true` (the feed is ~1.4 MB, over what a Worker step should parse); `parser: 'jvn'`; `pull: { heavy: { url: 'https://jvndb.jvn.jp/en/rss/jvndb.rdf' }, jobKind: 'first-load' }` (the server sends an ETag, so no `version` block) |
| `bsi-cert-bund` | `parser: 'cert-bund'`; `pull: { changelist: { listUrl: 'https://wid.cert-bund.de/.well-known/csaf/white/changes.csv', timeColumn: 1, refColumn: 0, itemUrl: 'https://wid.cert-bund.de/.well-known/csaf/white/{ref}' } }` |
| `cert-in` | No parser, no pull. Add a comment: the list pages answer "Page Requested Currently Not available" to a plain GET and no RSS or JSON list was found (24 Nov 2026); revisit when one exists |

Add a one-line comment above each change saying why. The CERT/CC feed orders by first publication, so an update to
an older note is not picked up; say so in the comment.

Before committing, `curl -sI` each URL (the CSV with `-r 0-511`) from the sandbox and save the status lines. If a
host is unreachable, say so in the PR; don't guess.

### 6. Fixtures (each folder gets `SOURCE.md`: URL, fetch date, licence `ask`, what was trimmed or invented)

Fetch real samples with curl and trim them; if a host is unreachable, hand-write the same shape and say so.

- `fixtures/cert-cc/atomfeed.xml`: the feed cut to three entries: one with four CVEs in its CVE IDs block and a
  fifth CVE only in the text (VU#604762 had this on 24 Nov), one with one CVE, one with none. Shorten
  `summary`/`content` prose to a sentence but keep the CVE IDs block. `note-604762.json`: the note API, prose
  fields shortened.
- `fixtures/jvn/jvndb.rdf`: the channel header and three items (one CVE, two CVEs, and a hand-edited item with no
  CVE and one unknown element `<sec:foo>`), plus a hand-written `bad-id.rdf` (one item, identifier `JVN#1`).
- `fixtures/bsi-cert-bund/changes-head.csv` (first 5 lines), `wid-sec-w-2026-4715.json` (real, `product_tree`
  trimmed), hand-written `amber.json` (TLP AMBER) and `no-cve.json`.

### 7. Tests (`packages/parsers/test/certs.test.ts`, `sources-certs.test.ts`; Node, fixtures only, no network)

- Each fixture through its parser: exact record counts, `sourceId`s, `vulnKey`s, `status`, `url`, millisecond UTC
  dates (JVN `+09:00` converted, BSI `+0000` accepted).
- CERT/CC: the text-only CVE is not linked; feed entry and note JSON for VU#604762 give the same CVE set; a bad
  `id` throws. JVN: `bad-id.rdf` gives no records and reports `item.sec:identifier`; a DOCTYPE throws; an item with
  1,200 CVEs keeps 1,000. BSI: `amber.json` → no records; `text: null` → none; bad JSON throws.
- Every produced `sourceId` passes the linker's `vulnId` (import it from `packages/linker/src/clean`).
- `link()` with the fake deps from `packages/linker/src/testing/fake-deps` over the CERT/CC and BSI records: each
  advisory with a CVE lands on that CVE's hub.
- `sources-certs.test.ts`: for the four sources, `loadParser` resolves (none for `cert-in`), the `pull` block
  matches the pattern, licences are still all `ask`, `jvn` is `heavy` with `jobKind: 'first-load'`. Run the
  changelist pattern's `fetch()` for `bsi-cert-bund` with `makeCtx`/`route`/`reply` from
  `packages/patterns/test/helpers`, serving `changes-head.csv` (206) and the document; expect items whose bodies
  parse to the fixture's records.

## Not in scope

- CERT/CC vendor statuses ("affected / not affected", `/vuls/api/<n>/vendors/vuls/`), a per-note fetch of the note
  API, backfill of older notes, and picking up updates to notes older than the feed's 15.
- JVN CPE products, CVSS, CWE, JVN#/JVNVU# ids as aliases, the Japanese feed, the MyJVN API, older JVNDB history.
- BSI product trees, TLP:GREEN feeds, signature checks (`.asc`), and the two other WHITE ROLIE feeds.
- CERT-In entirely (no stable feed); a `VulnRecord` for advisories without a CVE; changes to patterns, the collector,
  the linker, the registry, `csaf.ts` or `feed.ts`.

## Acceptance criteria

1. `pnpm build` (lint, typecheck, `pnpm test`) and `pnpm test:workers` pass; save both outputs.
2. `cert-common.ts`, `cert-cc.ts`, `jvn.ts` and `cert-bund.ts` export the names in sections 1–4.
3. The tests in section 7 pass on fixtures only; no test makes a network request.
4. `git diff --stat main -- packages/sources/src` shows only the four source files; paste the diff in the PR.
   Only `parser`, `pull`, the stated `pattern`/`heavy` changes and comments differ.
5. Proof saved: the `curl` status lines for each URL in section 5 (or a note that the host was unreachable), and a
   table of fixture → records (count, `sourceId`s, `vulnKey`s).
6. `rg "from 'node:" packages/parsers/src` is empty, and `git diff --stat main -- packages/parsers/src/csaf.ts
   packages/parsers/src/feed.ts fixtures/cert-in` is empty.
