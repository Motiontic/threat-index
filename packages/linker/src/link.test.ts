import type {
  AdvisoryRecord,
  IncidentRecord,
  NoticeRecord,
  ParsedRecord,
  TechniqueRecord,
  VulnRecord,
} from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { link } from './link';
import { KEV_EXPLOITED, KEV_RANSOMWARE, makeFake, NOW, vulnRow } from './testing/fake-deps';

const CVE = 'CVE-2025-3248';
const GHSA = 'GHSA-cfgh-jmpq-rvwx';
const NOW_ISO = NOW.toISOString();

const vuln = (key: string, over: Partial<VulnRecord> = {}): VulnRecord => ({
  key,
  kind: key.startsWith('CVE-') ? 'cve' : 'ghsa',
  title: `Title ${key}`,
  summary: 'Summary.',
  published: '2025-03-01',
  modified: '2025-03-02T00:00:00Z',
  cwe: [],
  aliases: [],
  source: key.startsWith('CVE-') ? 'cve-list' : 'github-advisory-db',
  ...over,
});
const advisory = (sourceId: string, over: Partial<AdvisoryRecord> = {}): AdvisoryRecord => ({
  source: 'github-advisory-db',
  sourceId,
  vulnKey: null,
  status: 'active',
  modified: '2025-03-02T00:00:00Z',
  ...over,
});
const tables = (rows: { table: string }[]) => rows.map((r) => r.table);
const changes = (rows: { table: string; row: Record<string, unknown> }[]) =>
  rows.filter((r) => r.table === 'changes').map((r) => r.row);

it('(a) KEV on a stored hot CVE: signal, kev_added, sources, one newly_exploited, docs', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE));
  const out = await link([KEV_EXPLOITED], f.deps);
  expect(tables(out.rows)).toEqual(['vulns', 'signals', 'changes']);
  const v = out.rows[0]?.row as Record<string, unknown>;
  expect(v.kev_added).toBe('2025-05-05');
  expect(JSON.parse(v.sources as string)).toEqual(['cisa-kev', 'cve-list']);
  expect(v.modified).toBe(NOW_ISO);
  expect(out.rows[1]?.row).toMatchObject({
    vuln_key: CVE,
    kind: 'exploited_wild',
    source: 'cisa-kev',
    ref: CVE,
  });
  expect(changes(out.rows)).toEqual([
    {
      id: 'id-1',
      entity_key: CVE,
      kind: 'newly_exploited',
      old: null,
      new: '2025-05-05',
      at: NOW_ISO,
      source: 'cisa-kev',
    },
  ]);
  expect(out.docs).toEqual([CVE]);
  expect(out.skipped).toBe(0);
});

it('(b) the same input after apply() gives no rows', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE));
  const input = [KEV_EXPLOITED, KEV_RANSOMWARE, vuln(CVE), advisory(GHSA, { vulnKey: CVE })];
  const first = await link(input, f.deps);
  expect(first.rows.length).toBeGreaterThan(0);
  f.apply(first.rows);
  const second = await link(input, f.deps);
  expect(second).toEqual({ rows: [], docs: [], skipped: 0 });
});

it('(c) promotes a cold CVE from its summary', async () => {
  const f = makeFake();
  f.cold.set(CVE, {
    key: 'WRONG',
    modified: 'WRONG',
    hot: 0,
    doc_key: 'WRONG',
    kind: 'cve',
    title: 'Langflow auth bypass',
    summary: 'cold summary',
    published: '2023-01-01',
    cvss: 9.8,
    cvss_version: 3.1, // wrong type: ignored
    cvss_source: 'nvd',
    ransomware: 'yes', // wrong type: ignored
    sources: '["cve-list"]',
  });
  const out = await link([KEV_EXPLOITED, KEV_RANSOMWARE], f.deps);
  expect(f.coldCalls).toEqual([CVE]);
  const v = out.rows.find((r) => r.table === 'vulns')?.row as Record<string, unknown>;
  expect(v).toMatchObject({
    key: CVE,
    title: 'Langflow auth bypass',
    summary: 'cold summary',
    published: '2023-01-01',
    cvss: 9.8,
    cvss_version: null,
    kev_added: '2025-05-05',
    ransomware: 1,
    hot: 1,
    doc_key: `docs/vuln/${CVE}.json`,
    modified: NOW_ISO,
  });
  expect(JSON.parse(v.sources as string)).toEqual(['cisa-kev', 'cve-list']);
  expect(changes(out.rows)).toHaveLength(1);
  expect(changes(out.rows)[0]).toMatchObject({ kind: 'newly_exploited', entity_key: CVE });
  expect(out.docs).toEqual([CVE]);
  expect(tables(out.rows)).toEqual(['vulns', 'signals', 'signals', 'changes']);
});

it('(c) promotes with a null summary: the key is the title, one change', async () => {
  const f = makeFake();
  const out = await link([KEV_EXPLOITED], f.deps);
  expect(f.coldCalls).toEqual([CVE]);
  expect(out.rows.find((r) => r.table === 'vulns')?.row).toMatchObject({
    key: CVE,
    title: CVE,
    kind: 'cve',
    kev_added: '2025-05-05',
  });
  expect(changes(out.rows)).toHaveLength(1);
  // a vuln record arriving later supplies the title
  const f2 = makeFake();
  const out2 = await link([KEV_EXPLOITED, vuln(CVE)], f2.deps);
  expect(out2.rows.find((r) => r.table === 'vulns')?.row).toMatchObject({ title: `Title ${CVE}` });
});

it('(d) a 2019 vuln record and a poc on a cold CVE are skipped, with no lookupCold', async () => {
  const f = makeFake();
  const old = await link([vuln('CVE-2019-0001', { published: '2019-01-01' })], f.deps);
  expect(old).toEqual({ rows: [], docs: [], skipped: 1 });
  const poc = await link(
    [{ vulnKey: 'CVE-2025-0009', kind: 'poc', source: 'edb', ref: 'EDB-1', firstSeen: '2025-02-01' }],
    f.deps,
  );
  expect(poc).toEqual({ rows: [], docs: [], skipped: 1 });
  expect(f.coldCalls).toEqual([]);
});

it('(e) a new 2025 vuln record inserts with no change rows', async () => {
  const f = makeFake();
  const out = await link([vuln('CVE-2025-0050')], f.deps);
  expect(tables(out.rows)).toEqual(['vulns']);
  expect(out.rows[0]?.row).toMatchObject({
    key: 'CVE-2025-0050',
    kind: 'cve',
    published: '2025-03-01',
    modified: NOW_ISO,
  });
  expect(out.docs).toEqual(['CVE-2025-0050']);
  f.apply(out.rows);
});

it('(f) an advisory with a CVE writes its own row and an alias row', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE));
  const out = await link([advisory(GHSA, { vulnKey: CVE, url: 'https://github.com/advisories/x' })], f.deps);
  expect(out.rows.map((r) => [r.table, r.row.source, r.row.source_id, r.row.vuln_key])).toEqual([
    ['vulns', undefined, undefined, undefined],
    ['advisories', 'github-advisory-db', GHSA, CVE],
    ['advisories', 'alias', GHSA, CVE],
  ]);
  expect(out.rows[2]?.row).toMatchObject({ status: 'active', modified: NOW_ISO });
  expect(out.docs).toEqual([CVE]);
});

it('(g) a stored GHSA row merges into its CVE, and a later signal on the GHSA lands on the CVE', async () => {
  const f = makeFake();
  f.put(
    'vulns',
    vulnRow(GHSA, {
      kev_added: '2025-01-01',
      ransomware: 1,
      cwe: '["CWE-1"]',
      sources: '["github-advisory-db"]',
      cvss: 7.5,
      cvss_version: '3.1',
      cvss_source: 'ghsa',
    }),
  );
  f.put('vulns', vulnRow(CVE, { cwe: '["CWE-2"]', kev_added: '2025-02-01', title: CVE }));
  const out = await link([vuln(CVE, { aliases: [GHSA], cwe: ['CWE-3'] })], f.deps);
  expect(out.rows.slice(0, 2).map((r) => [r.table, r.op])).toEqual([
    ['vulns', 'delete'],
    ['vulns', 'upsert'],
  ]);
  expect(out.rows[0]?.row).toEqual({ key: GHSA });
  const hub = out.rows[1]?.row as Record<string, unknown>;
  expect(hub).toMatchObject({
    key: CVE,
    kev_added: '2025-01-01',
    ransomware: 1,
    cvss: 7.5,
    cvss_source: 'ghsa',
  });
  expect(JSON.parse(hub.cwe as string)).toEqual(['CWE-1', 'CWE-2', 'CWE-3']);
  expect(JSON.parse(hub.sources as string)).toEqual(['cve-list', 'github-advisory-db']);
  expect(out.rows.find((r) => r.table === 'advisories')?.row).toMatchObject({
    source: 'alias',
    source_id: GHSA,
    vuln_key: CVE,
  });
  expect(changes(out.rows)).toEqual([]);
  f.apply(out.rows);
  expect(f.tables.vulns.size).toBe(1);

  const later = await link(
    [{ vulnKey: GHSA, kind: 'public_exploit', source: 'edb', ref: 'EDB-9', firstSeen: '2025-06-01' }],
    f.deps,
  );
  expect(later.rows.find((r) => r.table === 'signals')?.row).toMatchObject({ vuln_key: CVE });
  expect(later.docs).toEqual([CVE]);
});

it('(h) CVSS: same scorer ±1.0 changes, another scorer is ignored, ±0.5 updates silently', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE, { cvss: 7.0, cvss_version: '3.1', cvss_source: 'nvd' }));
  const same = await link([vuln(CVE, { cvss: 8.0, cvssSource: 'nvd', cvssVersion: '3.1' })], f.deps);
  expect(same.rows.find((r) => r.table === 'vulns')?.row).toMatchObject({ cvss: 8.0 });
  expect(changes(same.rows)).toMatchObject([{ kind: 'cvss_change', old: '7', new: '8', source: 'cve-list' }]);

  const other = await link([vuln(CVE, { cvss: 4.0, cvssSource: 'vendor' })], f.deps);
  expect(other.rows.find((r) => r.table === 'vulns')).toBeUndefined();
  expect(changes(other.rows)).toEqual([]);

  const small = await link([vuln(CVE, { cvss: 7.5, cvssSource: 'nvd' })], f.deps);
  expect(small.rows.find((r) => r.table === 'vulns')?.row).toMatchObject({ cvss: 7.5 });
  expect(changes(small.rows)).toEqual([]);

  const bad = await link([vuln(CVE, { cvss: 11, cvssSource: 'nvd' })], f.deps);
  expect(bad.rows.find((r) => r.table === 'vulns')).toBeUndefined();
});

it('(i) two new advisories with fixes give one fix_released', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE));
  const fix = [{ ecosystem: 'npm', name: 'x', fixed: '1.2.3' }];
  const out = await link(
    [
      advisory('GHSA-cfgh-jmpq-rvwx', { vulnKey: CVE, affected: fix }),
      advisory('GHSA-2345-6789-cfgh', { vulnKey: CVE, source: 'osv', affected: fix }),
    ],
    f.deps,
  );
  expect(changes(out.rows)).toMatchObject([
    { kind: 'fix_released', entity_key: CVE, source: 'github-advisory-db' },
  ]);
  // not for a flaw that had no row in D1
  const f2 = makeFake();
  const out2 = await link(
    [vuln('CVE-2025-0060'), advisory(GHSA, { vulnKey: 'CVE-2025-0060', affected: fix })],
    f2.deps,
  );
  expect(changes(out2.rows)).toEqual([]);
});

it('(j) public_exploit sets exploit_public and one change', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE));
  const out = await link(
    [{ vulnKey: CVE, kind: 'public_exploit', source: 'metasploit', ref: 'm/1', firstSeen: '2025-06-01' }],
    f.deps,
  );
  expect(out.rows.find((r) => r.table === 'vulns')?.row).toMatchObject({ exploit_public: 1 });
  expect(changes(out.rows)).toMatchObject([
    { kind: 'public_exploit', old: 'no', new: 'yes', source: 'metasploit' },
  ]);
  // a poc changes no column
  const poc = await link(
    [{ vulnKey: CVE, kind: 'poc', source: 'edb', ref: 'e', firstSeen: '2025-06-01' }],
    f.deps,
  );
  expect(tables(poc.rows)).toEqual(['vulns', 'signals']); // `sources` gains the new source
  expect(changes(poc.rows)).toEqual([]);
});

it('(k) notices with and without a company key; unchanged incidents and techniques', async () => {
  const f = makeFake();
  const n1: NoticeRecord = {
    source: 'ca-ag',
    noticeId: 'n1',
    rawName: 'Acme Inc',
    companyKey: 'acme',
    countUnit: 'state_residents',
    count: 10,
    url: 'https://x.test/n1',
  };
  const n2: NoticeRecord = {
    source: 'ca-ag',
    noticeId: 'n2',
    rawName: 'Nobody LLC',
    countUnit: 'not_stated',
    count: -5,
  };
  const inc: IncidentRecord = {
    source: 'aiid',
    incidentId: 'i1',
    kind: 'ai',
    title: 'T',
    entities: ['b', 'a', 'a'],
  };
  const tech: TechniqueRecord = {
    id: 'T1190',
    framework: 'attack',
    name: 'Exploit Public-Facing Application',
  };
  const input: ParsedRecord[] = [n1, n2, inc, tech];
  const out = await link(input, f.deps);
  expect(tables(out.rows)).toEqual([
    'techniques',
    'companies',
    'companies',
    'breach_events',
    'breach_events',
    'breach_notices',
    'breach_notices',
    'incidents',
    'changes',
    'changes',
  ]);
  // `companyKey: 'acme'` is not a hint (no cik:/domain: prefix), so both notices are matched by name
  expect(changes(out.rows)).toMatchObject([
    { kind: 'breach_notice', entity_key: 'name:acme:xx', new: 'ca-ag:n1', source: 'ca-ag' },
    { kind: 'breach_notice', entity_key: 'name:nobody:xx', new: 'ca-ag:n2', source: 'ca-ag' },
  ]);
  expect(out.rows.find((r) => r.table === 'incidents')?.row).toMatchObject({
    entities: '["a","b"]',
    gated: 0,
    modified: NOW_ISO,
  });
  expect(out.rows.filter((r) => r.table === 'breach_notices')[1]?.row).toMatchObject({
    count: null,
    company_key: 'name:nobody:xx',
    name_key: 'nobody',
  });
  expect(out.docs).toEqual([]);
  f.apply(out.rows);
  expect(await link(input, f.deps)).toEqual({ rows: [], docs: [], skipped: 0 });
  // stored values survive: event_key, company_key, gated; a count is never summed
  f.put('breach_notices', {
    ...(f.tables.breach_notices.values().next().value as object),
    event_key: 'ev1',
    count: 10,
  });
  f.put('incidents', { ...(f.tables.incidents.values().next().value as object), gated: 1 });
  const again = await link(
    [
      { ...n1, companyKey: undefined, count: 99, rawName: 'Acme Incorporated' },
      { ...inc, title: 'T2' },
    ],
    f.deps,
  );
  expect(again.rows.find((r) => r.table === 'breach_notices')?.row).toMatchObject({
    event_key: 'ev1',
    company_key: 'name:acme:xx',
    count: 99,
    raw_name: 'Acme Incorporated',
  });
  expect(again.rows.find((r) => r.table === 'incidents')?.row).toMatchObject({ gated: 1, title: 'T2' });
  expect(changes(again.rows)).toEqual([]);
});

it('(l) each table is read at most once (breach_notices three times): advisories, then vulns, then signals', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE));
  await link(
    [
      KEV_EXPLOITED,
      vuln(CVE, { aliases: [GHSA] }),
      vuln('CVE-2025-0070'),
      advisory(GHSA, { vulnKey: CVE }),
      { source: 'ca-ag', noticeId: 'n1', rawName: 'A', countUnit: 'claim' },
      { id: 'T1', framework: 'attack', name: 'n' },
      { source: 'aiid', incidentId: 'i', kind: 'ai', title: 't' },
    ],
    f.deps,
  );
  const seen = f.reads.map((r) => r.table);
  // breach_notices: by key, by name_key, by company_key; every other table once
  expect(seen.filter((t) => t === 'breach_notices')).toHaveLength(3);
  expect(new Set(seen).size).toBe(seen.length - 2);
  expect(seen.indexOf('advisories')).toBeLessThan(seen.indexOf('vulns'));
  expect(seen.indexOf('vulns')).toBeLessThan(seen.indexOf('signals'));
  expect(seen.sort()).toEqual([
    'advisories',
    'breach_notices',
    'breach_notices',
    'breach_notices',
    'companies',
    'incidents',
    'signals',
    'techniques',
    'vulns',
  ]);
  // the keys are primary-key objects with real column names
  expect(f.reads.find((r) => r.table === 'advisories')?.keys).toContainEqual({
    source: 'alias',
    source_id: GHSA,
  });
  expect(f.reads.filter((r) => r.table === 'breach_notices').map((r) => r.keys)).toEqual([
    [{ source: 'ca-ag', notice_id: 'n1' }],
    [{ name_key: 'a' }],
    [{ company_key: 'name:a:xx' }],
  ]);
  expect(f.reads.find((r) => r.table === 'signals')?.keys).toEqual([
    { vuln_key: CVE, kind: 'exploited_wild', source: 'cisa-kev', ref: CVE },
  ]);
  // never with an empty list, and not at all for an empty call
  const empty = makeFake();
  expect(await link([], empty.deps)).toEqual({ rows: [], docs: [], skipped: 0 });
  expect(empty.reads).toEqual([]);
  await link([vuln('CVE-2019-0002', { published: '2018-01-01' })], empty.deps);
  expect(empty.reads.map((r) => r.table)).toEqual(['vulns']); // no non-CVE ID, so no advisories read
});

it('(m) a javascript: URL is stored as null and a 400-char summary is cut to 300', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE, { summary: null, title: CVE }));
  const out = await link(
    [vuln(CVE, { summary: 'x'.repeat(400) }), advisory(GHSA, { vulnKey: CVE, url: 'javascript:alert(1)' })],
    f.deps,
  );
  expect(String(out.rows[0]?.row.summary).length).toBe(300);
  expect(out.rows.find((r) => r.table === 'advisories' && r.row.source !== 'alias')?.row.url).toBeNull();
});

it('drops unsafe IDs and counts them as skipped', async () => {
  const f = makeFake();
  const out = await link([vuln('../x'), vuln(''), advisory('a/b')], f.deps);
  expect(out).toEqual({ rows: [], docs: [], skipped: 3 });
});

it('one hub claims a merged ID; two CVEs are never aliased or merged', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(GHSA));
  const out = await link(
    [vuln('CVE-2025-0001', { aliases: [GHSA, 'CVE-2025-0002'] }), vuln('CVE-2025-0002', { aliases: [GHSA] })],
    f.deps,
  );
  expect(out.rows.filter((r) => r.op === 'delete')).toHaveLength(1);
  expect(out.rows.filter((r) => r.table === 'advisories')).toHaveLength(1);
  expect(out.rows.filter((r) => r.table === 'advisories').every((r) => r.row.source_id === GHSA)).toBe(true);
});

it('rows follow ROW_ORDER with changes last', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE));
  const out = await link(
    [
      { source: 'ca-ag', noticeId: 'n1', rawName: 'A', companyKey: 'a', countUnit: 'claim' },
      KEV_EXPLOITED,
      advisory(GHSA, { vulnKey: CVE }),
    ],
    f.deps,
  );
  expect(tables(out.rows)).toEqual([
    'vulns',
    'advisories',
    'advisories',
    'signals',
    'companies',
    'breach_events',
    'breach_notices',
    'changes',
    'changes',
  ]);
});

const pkgRec = (over: Partial<AdvisoryRecord> = {}): AdvisoryRecord =>
  advisory('GHSA-pppp-qqqq-rrrr', {
    vulnKey: null,
    affected: [{ ecosystem: 'npm', name: 'left-pad', rangeType: 'ECOSYSTEM', fixed: '1.3.0' }],
    reviewed: true,
    ...over,
  });

it('(pkg) a cold record gets package rows, and linking it again gives none', async () => {
  const f = makeFake();
  const out = await link([pkgRec({ modified: '2019-01-01T00:00:00Z' })], f.deps);
  expect(tables(out.rows)).toEqual(['affected', 'package_advisories']);
  expect(out.skipped).toBe(1);
  f.apply(out.rows);
  const again = await link([pkgRec({ modified: '2019-01-01T00:00:00Z' })], f.deps);
  expect(again.rows).toEqual([]);
});

it('(pkg) package rows sit before changes, and each new table is read once', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE));
  const out = await link(
    [
      advisory(GHSA, {
        vulnKey: CVE,
        affected: [{ ecosystem: 'npm', name: 'a', rangeType: 'ECOSYSTEM', fixed: '1' }],
      }),
      pkgRec(),
      pkgRec({ sourceId: 'GHSA-xxxx-yyyy-zzzz' }),
    ],
    f.deps,
  );
  const t = tables(out.rows);
  const firstPkg = t.indexOf('affected');
  expect(firstPkg).toBeGreaterThan(-1);
  if (t.includes('changes')) expect(t.lastIndexOf('package_advisories')).toBeLessThan(t.indexOf('changes'));
  expect(f.reads.filter((x) => x.table === 'package_advisories')).toHaveLength(1);
  expect(f.reads.filter((x) => x.table === 'affected')).toHaveLength(1);
  expect(out.rows.filter((x) => x.table === 'package_advisories')).toHaveLength(3);
});

it('(pkg) a cve-list advisory with a fix on a stored hot vuln raises no fix_released', async () => {
  const f = makeFake();
  f.put('vulns', vulnRow(CVE));
  const out = await link(
    [
      advisory(CVE, {
        source: 'cve-list',
        vulnKey: CVE,
        affected: [
          { ecosystem: 'PyPI', name: 'langflow', rangeType: 'ECOSYSTEM', introduced: '0', fixed: '1.3.0' },
        ],
      }),
    ],
    f.deps,
  );
  expect(changes(out.rows).filter((c) => c.kind === 'fix_released')).toEqual([]);
  expect(tables(out.rows)).toContain('advisories');
  expect(tables(out.rows)).toContain('package_advisories');
});

it('(pkg) when read returns nothing, rows are upserts only', async () => {
  const f = makeFake();
  const out = await link([pkgRec()], f.deps);
  expect(
    out.rows
      .filter((x) => x.table === 'affected' || x.table === 'package_advisories')
      .every((x) => x.op === 'upsert'),
  ).toBe(true);
});

it('(pkg) a record that drops a package deletes its rows in the same output', async () => {
  const f = makeFake();
  const two = pkgRec({
    affected: [
      { ecosystem: 'npm', name: 'a', rangeType: 'ECOSYSTEM', fixed: '1' },
      { ecosystem: 'npm', name: 'b', rangeType: 'ECOSYSTEM', fixed: '1' },
    ],
  });
  f.apply((await link([two], f.deps)).rows);
  const out = await link(
    [
      pkgRec({
        modified: '2026-01-01T00:00:00Z',
        affected: [{ ecosystem: 'npm', name: 'a', rangeType: 'ECOSYSTEM', fixed: '1' }],
      }),
    ],
    f.deps,
  );
  expect(out.rows.filter((x) => x.table === 'affected' && x.op === 'delete').map((x) => x.row.name)).toEqual([
    'b',
  ]);
  f.apply(out.rows);
  expect([...f.pkg.affected.values()].map((r) => r.name)).toEqual(['a']);
});

describe('(new_advisory)', () => {
  const recent = (over: Partial<AdvisoryRecord> = {}) => pkgRec({ published: '2026-02-25', ...over });
  const newAdv = (rows: { table: string; row: Record<string, unknown> }[]) =>
    changes(rows).filter((c) => c.kind === 'new_advisory');

  it('a first insert of a recent active advisory with packages writes exactly one change', async () => {
    const f = makeFake();
    const out = await link([recent()], f.deps);
    expect(newAdv(out.rows)).toEqual([
      {
        id: 'new_advisory:GHSA-pppp-qqqq-rrrr',
        entity_key: 'GHSA-pppp-qqqq-rrrr',
        kind: 'new_advisory',
        old: null,
        new: 'github-advisory-db:GHSA-pppp-qqqq-rrrr',
        at: NOW_ISO,
        source: 'github-advisory-db',
      },
    ]);
    expect(out.newAdvisories).toBe(1);
  });

  it('an update of a stored advisory writes none', async () => {
    const f = makeFake();
    f.apply((await link([recent()], f.deps)).rows);
    const out = await link([recent({ modified: '2026-02-27T00:00:00Z' })], f.deps);
    expect(tables(out.rows)).toContain('package_advisories');
    expect(newAdv(out.rows)).toEqual([]);
    expect(out.newAdvisories ?? 0).toBe(0);
  });

  it('an old record, a record without published, a withdrawn one and one without packages write none', async () => {
    const f = makeFake();
    const out = await link(
      [
        recent({ sourceId: 'GHSA-old1-old1-old1', published: '2026-02-01' }),
        pkgRec({ sourceId: 'GHSA-nopu-nopu-nopu' }),
        recent({ sourceId: 'GHSA-wdrw-wdrw-wdrw', status: 'withdrawn' }),
        recent({ sourceId: 'GHSA-nopk-nopk-nopk', affected: [] }),
      ],
      f.deps,
    );
    expect(newAdv(out.rows)).toEqual([]);
  });

  it('the same vuln from two sources gives one row', async () => {
    const f = makeFake();
    const out = await link(
      [recent({ vulnKey: CVE }), recent({ source: 'osv', sourceId: 'GHSA-pppp-qqqq-rrrr', vulnKey: CVE })],
      f.deps,
    );
    expect(newAdv(out.rows).map((c) => c.id)).toEqual([`new_advisory:${CVE}`]);
  });

  it('packageWrites alone (the affected backfill) never makes a changes row', async () => {
    const { affectedRows, packageWrites } = await import('./affected');
    const r = recent();
    const rows = packageWrites(r, affectedRows(r), { ranges: [] });
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.some((x) => x.table === 'changes')).toBe(false);
  });
});
