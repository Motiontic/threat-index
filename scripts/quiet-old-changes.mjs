// Marks the backlog of `changes` rows that must not alert: events older than the alert window and the rows a
// source's first load wrote. Dry run by default; `--apply` writes. Runs from a laptop where wrangler is logged in
// (like scripts/deploy.mjs); it cannot run in a loop sandbox.
//
//   node scripts/quiet-old-changes.mjs --env staging|production [--apply]
//
// It touches only rows with `quiet IS NULL` and sets only `event_at` and `quiet`. It never deletes and never
// holds rows. A second run changes nothing. The rule lives in packages/linker/src/age.ts; the planning in
// scripts/lib/quiet-plan.mjs (pure, tested); this file is the thin wrangler part.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { firstLoadBoundaries, planQuiet, updateChunks } from './lib/quiet-plan.mjs';
import { loadDotEnv, ROOT, writeDeployConfig } from './wrangler-config.mjs';

const PAGE = 10_000;
const lit = (v) => `'${String(v).replaceAll("'", "''")}'`;

function parseArgs(argv) {
  const out = { env: null, apply: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--apply') out.apply = true;
    else if (argv[i] === '--env') out.env = argv[++i] ?? null;
    else throw new Error(`unknown argument ${argv[i]}`);
  }
  if (out.env !== 'staging' && out.env !== 'production')
    throw new Error('usage: node scripts/quiet-old-changes.mjs --env staging|production [--apply]');
  return out;
}

function makeD1(target, config) {
  const suffix = target === 'staging' ? '_staging' : '';
  const base = (db) => [
    'd1',
    'execute',
    db + suffix,
    '--remote',
    ...(target === 'staging' ? ['--env', 'staging'] : []),
    '-c',
    config,
  ];
  const wrangler = (args) =>
    execFileSync(join(ROOT, 'node_modules', '.bin', 'wrangler'), args, {
      cwd: ROOT,
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
      env: { ...process.env, CI: process.env.CI ?? '1' },
      stdio: ['ignore', 'pipe', 'inherit'],
    });
  return {
    query(db, sql) {
      const res = JSON.parse(wrangler([...base(db), '--json', '--command', sql]));
      return res[0]?.results ?? [];
    },
    file(db, path) {
      wrangler([...base(db), '--file', path]);
    },
  };
}

/** Reads every row of a query, at most PAGE per call; `after(row)` is the keyset condition for the next page. */
function readAll(d1, db, select, after) {
  const rows = [];
  let cond = '';
  for (;;) {
    const page = d1.query(db, select(cond, PAGE));
    rows.push(...page);
    if (page.length < PAGE) return rows;
    cond = after(page[page.length - 1]);
  }
}

function load(d1) {
  const changes = readAll(
    d1,
    'ti_signals',
    (cond, n) =>
      `SELECT id, kind, source, entity_key, new, at, event_at, quiet FROM changes WHERE quiet IS NULL${cond} ORDER BY id LIMIT ${n}`,
    (r) => ` AND id > ${lit(r.id)}`,
  );
  const exploit = new Map(
    readAll(
      d1,
      'ti_signals',
      (cond, n) =>
        `SELECT vuln_key, MIN(first_seen) AS d FROM signals WHERE kind = 'public_exploit'${cond} GROUP BY vuln_key ORDER BY vuln_key LIMIT ${n}`,
      (r) => ` AND vuln_key > ${lit(r.vuln_key)}`,
    ).map((r) => [r.vuln_key, r.d]),
  );
  const fix = new Map(
    readAll(
      d1,
      'ti_advisories',
      (cond, n) =>
        `SELECT source, vuln_key, COALESCE(MIN(published), MIN(modified)) AS d FROM advisories WHERE vuln_key IS NOT NULL${cond} GROUP BY source, vuln_key ORDER BY source, vuln_key LIMIT ${n}`,
      (r) => ` AND (source, vuln_key) > (${lit(r.source)}, ${lit(r.vuln_key)})`,
    ).map((r) => [`${r.source}\u0000${r.vuln_key}`, r.d]),
  );
  const notice = new Map(
    readAll(
      d1,
      'ti_world',
      (cond, n) =>
        `SELECT source, notice_id, COALESCE(notified, discovered) AS d FROM breach_notices WHERE 1 = 1${cond} ORDER BY source, notice_id LIMIT ${n}`,
      (r) => ` AND (source, notice_id) > (${lit(r.source)}, ${lit(r.notice_id)})`,
    )
      .filter((r) => r.d)
      .map((r) => [`${r.source}:${r.notice_id}`, r.d]),
  );
  const runs = readAll(
    d1,
    'ti_control',
    (cond, n) =>
      `SELECT id, source_id, status, error, started_at, finished_at FROM runs WHERE 1 = 1${cond} ORDER BY id LIMIT ${n}`,
    (r) => ` AND id > ${lit(r.id)}`,
  );
  const jobs = readAll(
    d1,
    'ti_control',
    (cond, n) =>
      `SELECT id, kind, source_id, status, created_at, finished_at FROM jobs WHERE 1 = 1${cond} ORDER BY id LIMIT ${n}`,
    (r) => ` AND id > ${lit(r.id)}`,
  );
  return { changes, exploit, fix, notice, boundaries: firstLoadBoundaries(runs, jobs) };
}

function main() {
  const { env: target, apply } = parseArgs(process.argv.slice(2));
  loadDotEnv();
  const config = writeDeployConfig('api', target);
  const d1 = makeD1(target, config);
  const data = load(d1);
  const { updates, summary } = planQuiet(data.changes, data);
  console.log(`${target}: ${data.changes.length} alertable rows read, ${updates.length} to update`);
  console.log('kind\tsource\treason\trows');
  for (const s of summary) console.log(`${s.kind}\t${s.source}\t${s.reason}\t${s.rows}`);
  if (!apply) {
    console.log('dry run: nothing written. Add --apply to write.');
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), 'quiet-changes-'));
  try {
    const chunks = updateChunks(updates);
    chunks.forEach((sql, i) => {
      const path = join(dir, `chunk-${i}.sql`);
      writeFileSync(path, sql);
      d1.file('ti_signals', path);
      console.log(`wrote chunk ${i + 1}/${chunks.length}`);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
