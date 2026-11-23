import type { ParsedRecord } from '@ti/core/types';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { link } from '../../linker/src/link';
import { makeFake } from '../../linker/src/testing/fake-deps';
import { fetch as fingerprintFetch } from '../../patterns/src/fingerprint';
import { makeCtx, reply, route } from '../../patterns/test/helpers';
import { parseAiaaicRow } from '../src/aiaaic';
import { parseAvid } from '../src/avid';
import { parseCfrRow } from '../src/cfr-cyber-ops';

async function csvRecords(id: string, parse: (b: unknown) => { records: ParsedRecord[] }) {
  const source = SOURCE_BY_ID.get(id);
  const url = source?.pull?.fingerprint?.url;
  if (!source || !url) throw new Error(`no pull for ${id}`);
  const h = makeCtx({
    source,
    routes: [route(url, reply(fixture(id, 'incidents.csv'), 200, { 'content-type': 'text/csv' }))],
  });
  return (await fingerprintFetch(h.ctx)).items.flatMap((i) => parse(i.body).records);
}

describe('parsed incident records through link()', () => {
  it('writes incidents keyed (source, incident_id); a second link writes nothing', async () => {
    const records: ParsedRecord[] = [
      ...['AVID-2026-R1714.json', 'AVID-2022-R0001.json', 'AVID-2023-V028.json'].flatMap(
        (f) => parseAvid(fixture('avid', f)).records,
      ),
      ...(await csvRecords('aiaaic', parseAiaaicRow)),
      ...(await csvRecords('cfr-tracker', parseCfrRow)),
    ];
    const f = makeFake();
    const out = await link(records, f.deps);
    f.apply(out.rows);

    const rows = f.all('incidents');
    expect(rows).toHaveLength(3 + 6 + 7);
    expect(new Set(rows.map((r) => `${r.source}:${r.incident_id}`)).size).toBe(rows.length);
    const kinds = (s: string) => new Set(rows.filter((r) => r.source === s).map((r) => r.kind));
    expect(kinds('avid')).toEqual(new Set(['ai']));
    expect(kinds('aiaaic')).toEqual(new Set(['ai']));
    expect(kinds('cfr-tracker')).toEqual(new Set(['cyber_op']));
    for (const r of rows) {
      expect(Array.isArray(JSON.parse(r.entities as string))).toBe(true);
      if (r.source === 'aiaaic') expect(r.date).toBeNull();
    }
    const r1714 = rows.find((r) => r.incident_id === 'AVID-2026-R1714');
    expect(JSON.parse(r1714?.techniques as string)).toEqual(['CWE-506']);

    if (process.env.TI_PROOF_LINK) console.log(JSON.stringify({ incidents: rows }, null, 2));

    const again = await link(records, f.deps);
    expect(again.rows.filter((r) => r.table === 'incidents')).toEqual([]);
  });
});
