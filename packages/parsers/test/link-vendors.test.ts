import type { AdvisoryRecord, SignalRecord } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { link } from '../../linker/src/link';
import { makeFake, vulnRow } from '../../linker/src/testing/fake-deps';
import { parseCsaf } from '../src/csaf';

describe('parsed vendor advisories through link()', () => {
  it('one advisories row per (source, sourceId), the MSRC signal on its own row, a fix source for Red Hat', async () => {
    const f = makeFake();
    const docs: Array<[string, string]> = [
      ['red-hat', 'cve-2023-38545.json'],
      ['msrc', 'msrc_cve-2024-38193.json'],
      ['msrc', 'msrc_cve-2026-70197.json'],
      ['cisco', 'cisco-sa-fmc-mulivulns-4psnfwvx.json'],
      ['oracle', 'cpujan2025csaf.json'],
    ];
    const records: Array<AdvisoryRecord | SignalRecord> = docs.flatMap(
      ([s, file]) => parseCsaf(fixture(s, file)).records,
    );
    for (const r of records) f.put('vulns', vulnRow(r.vulnKey as string));
    const out = await link(records, f.deps);
    f.apply(out.rows);

    // The linker also writes `alias` rows into this table; they are not vendor advisories.
    const advs = f.all('advisories').filter((a) => a.source !== 'alias');
    const keys = advs.map((a) => `${a.source}|${a.source_id}`);
    expect(new Set(keys).size).toBe(keys.length);
    expect(advs).toHaveLength(1 + 2 + 5 + 3);
    for (const a of advs) expect(a.vuln_key).toMatch(/^CVE-/);
    expect(advs.find((a) => a.source === 'red-hat')).toMatchObject({
      source_id: 'CVE-2023-38545',
      vuln_key: 'CVE-2023-38545',
    });

    const sigs = f.all('signals');
    expect(sigs).toHaveLength(1);
    expect(sigs[0]).toMatchObject({ vuln_key: 'CVE-2024-38193', kind: 'exploited_wild', source: 'msrc' });
    for (const v of f.all('vulns')) expect(v.kev_added ?? null).toBeNull();

    const changes = f.all('changes');
    expect(
      changes.some(
        (c) => c.kind === 'fix_released' && c.entity_key === 'CVE-2023-38545' && c.source === 'red-hat',
      ),
    ).toBe(true);

    if (process.env.TI_PROOF_LINK)
      console.log(
        JSON.stringify(
          Object.fromEntries(
            (['vulns', 'signals', 'advisories', 'changes'] as const).map((t) => [t, f.all(t)]),
          ),
          null,
          2,
        ),
      );
  });
});
