import { lookupVulnKey } from '@ti/core/r2-keys';
import { beforeEach, expect, it } from 'vitest';
import { linkDeps } from '../src/link-deps';
import { E, NOW, reset } from './helpers';

const deps = () => linkDeps(E, { now: () => NOW, newId: () => 'id' });

beforeEach(async () => {
  await reset();
  await E.DB_VULNS.prepare('DELETE FROM vulns').run();
  await E.DB_SIGNALS.prepare('DELETE FROM signals').run();
});

it('reads rows by single-column keys, in as many statements as needed (> 100 keys)', async () => {
  const rows = Array.from({ length: 250 }, (_, i) => `CVE-2024-${1000 + i}`);
  await E.DB_VULNS.batch(
    rows.map((k) =>
      E.DB_VULNS.prepare("INSERT INTO vulns (key, kind, title, modified) VALUES (?1, 'cve', 't', 'm')").bind(
        k,
      ),
    ),
  );
  const got = await deps().read(
    'vulns',
    [...rows, 'CVE-2099-1'].map((key) => ({ key })),
  );
  expect(got).toHaveLength(250);
  expect(got[0]).toHaveProperty('title', 't');
});

it('reads rows by composite keys with row-value IN', async () => {
  await E.DB_SIGNALS.batch([
    E.DB_SIGNALS.prepare(
      "INSERT INTO signals (vuln_key, kind, source, ref, first_seen) VALUES ('CVE-1','poc','s','r1','d')",
    ),
    E.DB_SIGNALS.prepare(
      "INSERT INTO signals (vuln_key, kind, source, ref, first_seen) VALUES ('CVE-1','poc','s','r2','d')",
    ),
  ]);
  const got = await deps().read('signals', [
    { vuln_key: 'CVE-1', kind: 'poc', source: 's', ref: 'r2' },
    { vuln_key: 'CVE-1', kind: 'poc', source: 's', ref: 'nope' },
  ]);
  expect(got.map((r) => r.ref)).toEqual(['r2']);
});

it('refuses ti_users and ti_control tables, bad names and unknown tables', async () => {
  const d = deps();
  await expect(d.read('runs', [{ id: 'x' }])).rejects.toThrow();
  await expect(d.read('cursors', [{ source_id: 'x' }])).rejects.toThrow();
  await expect(d.read('users', [{ id: 'x' }])).rejects.toThrow();
  await expect(d.read('vulns; DROP TABLE vulns', [{ key: 'x' }])).rejects.toThrow();
  await expect(d.read('vulns', [{ 'key) OR 1=1 --': 'x' }])).rejects.toThrow();
  await expect(d.read('vulns', [{ key: 'a' }, { other: 'b' }])).rejects.toThrow();
  expect(await d.read('vulns', [])).toEqual([]);
});

it('lookupCold returns the key row from the shard file, or null', async () => {
  const d = deps();
  expect(await d.lookupCold('CVE-2024-1234')).toBeNull(); // no file yet
  await E.BUCKET.put(
    lookupVulnKey('CVE-2024-1234'),
    JSON.stringify({ 'CVE-2024-1234': { key: 'CVE-2024-1234', title: 'cold' } }),
  );
  expect(await d.lookupCold('cve-2024-1234')).toEqual({ key: 'CVE-2024-1234', title: 'cold' });
  expect(await d.lookupCold('CVE-2024-1234')).toMatchObject({ title: 'cold' });
  await E.BUCKET.put(lookupVulnKey('CVE-2024-1234'), JSON.stringify({ 'CVE-2024-2222': {} }));
  expect(await d.lookupCold('CVE-2024-1234')).toBeNull();
});
