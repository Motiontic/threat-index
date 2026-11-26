import { expect, it } from 'vitest';
import { AFFECTED_COLUMNS, AFFECTED_KEY, PACKAGE_ADVISORY_COLUMNS } from './affected';
import {
  ADVISORY_STATUSES,
  CHANGE_KINDS,
  COLUMNS,
  INCIDENT_KINDS,
  type LinkTable,
  PRIMARY_KEYS,
  SIGNAL_KINDS,
} from './tables';

interface GlobImportMeta {
  glob(pattern: string, options: { query: string; import: string; eager: true }): Record<string, string>;
}
const files = (import.meta as unknown as GlobImportMeta).glob('../../db/migrations/*/*.sql', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const sql = Object.values(files).join('\n');

interface Col {
  name: string;
  required: boolean; // NOT NULL (or primary key) with no default
}

function splitTop(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = '';
  let quoted = false;
  for (const ch of body) {
    if (ch === "'") quoted = !quoted;
    if (quoted) {
      cur += ch;
      continue;
    }
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      parts.push(cur.trim());
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

function parseTables(
  text: string,
): Map<string, { cols: Col[]; pk: string[]; checks: Map<string, string[]> }> {
  const out = new Map<string, { cols: Col[]; pk: string[]; checks: Map<string, string[]> }>();
  const clean = text.replace(/--[^\n]*/g, '');
  for (const m of clean.matchAll(/CREATE TABLE (\w+) \(([\s\S]*?)\)\s*(?:WITHOUT ROWID)?\s*;/g)) {
    const [, name, body] = m as unknown as [string, string, string];
    const cols: Col[] = [];
    let pk: string[] = [];
    const checks = new Map<string, string[]>();
    for (const part of splitTop(body)) {
      const tablePk = /^PRIMARY KEY \(([^)]*)\)/.exec(part);
      if (tablePk) {
        pk = (tablePk[1] as string).split(',').map((s) => s.trim());
        continue;
      }
      const colName = (/^(\w+)/.exec(part) as RegExpExecArray)[1] as string;
      const inlinePk = /PRIMARY KEY/.test(part);
      if (inlinePk) pk = [colName];
      cols.push({ name: colName, required: (/NOT NULL/.test(part) || inlinePk) && !/DEFAULT/.test(part) });
      const check = /CHECK \(\w+ IN \(([^)]*)\)\)/.exec(part);
      if (check)
        checks.set(
          colName,
          [...(check[1] as string).matchAll(/'([^']*)'/g)].map((x) => x[1] as string),
        );
    }
    out.set(name, { cols, pk, checks });
  }
  // A rebuilt table (CREATE TABLE x_new ... ALTER TABLE x_new RENAME TO x) replaces the old definition.
  for (const m of clean.matchAll(/ALTER TABLE (\w+) RENAME TO (\w+)\s*;/g)) {
    const [, from, to] = m as unknown as [string, string, string];
    const t = out.get(from);
    if (!t) throw new Error(`RENAME of unknown table ${from}`);
    out.set(to, t);
    out.delete(from);
  }
  // Later migrations add columns with ALTER TABLE ... ADD COLUMN, in file order.
  for (const m of clean.matchAll(/ALTER TABLE (\w+) ADD COLUMN (\w+)([^;]*);/g)) {
    const [, name, col, rest] = m as unknown as [string, string, string, string];
    const t = out.get(name);
    if (!t) throw new Error(`ALTER TABLE on unknown table ${name}`);
    t.cols.push({ name: col, required: /NOT NULL/.test(rest) && !/DEFAULT/.test(rest) });
  }
  return out;
}

const tables = parseTables(sql);
const linked = Object.keys(COLUMNS) as LinkTable[];

it('the migrations declare every table the linker writes', () => {
  for (const t of linked) expect(tables.has(t), t).toBe(true);
});

it.each(linked)('COLUMNS and PRIMARY_KEYS for %s equal the CREATE TABLE', (t) => {
  const sqlTable = tables.get(t);
  expect(COLUMNS[t]).toEqual(sqlTable?.cols.map((c) => c.name));
  expect(PRIMARY_KEYS[t]).toEqual(sqlTable?.pk);
});

it.each(linked)('every NOT NULL column without a default in %s is always written', (t) => {
  for (const c of tables.get(t)?.cols ?? []) if (c.required) expect(COLUMNS[t]).toContain(c.name);
});

it('change and signal kinds equal the CHECK lists', () => {
  expect([...CHANGE_KINDS].sort()).toEqual([...(tables.get('changes')?.checks.get('kind') ?? [])].sort());
  expect([...SIGNAL_KINDS].sort()).toEqual([...(tables.get('signals')?.checks.get('kind') ?? [])].sort());
  expect([...ADVISORY_STATUSES].sort()).toEqual(
    [...(tables.get('advisories')?.checks.get('status') ?? [])].sort(),
  );
  expect([...INCIDENT_KINDS].sort()).toEqual([...(tables.get('incidents')?.checks.get('kind') ?? [])].sort());
});

it('the package-table columns and keys equal the CREATE TABLEs in migration 0002', () => {
  expect([...AFFECTED_COLUMNS]).toEqual(tables.get('affected')?.cols.map((c) => c.name));
  expect([...AFFECTED_KEY]).toEqual(tables.get('affected')?.pk);
  expect([...PACKAGE_ADVISORY_COLUMNS]).toEqual(tables.get('package_advisories')?.cols.map((c) => c.name));
});
