import type { ParsedRecord } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { link } from '../../linker/src/link';
import { makeFake, vulnRow } from '../../linker/src/testing/fake-deps';
import { parseEuvd } from '../src/euvd';
import { parseGcveSightings } from '../src/gcve-sighting';
import { parseProjectZeroRow } from '../src/project-zero';

describe('parsed sighting records through link()', () => {
  it('keeps one signals row per source, never sets kev_added, and links EUVD advisories and vulns', async () => {
    const f = makeFake();
    // A CVE signal lands only on a stored (hot) hub, so seed the two CVEs the fixtures mention.
    f.put('vulns', vulnRow('CVE-2026-134624'));
    f.put('vulns', vulnRow('CVE-2026-114713'));
    const pzRows = fixture('project-zero', 'all.csv').split('\r\n').slice(1);
    const records: ParsedRecord[] = [
      ...parseEuvd(fixture('enisa', 'exploited-search.json')).records,
      ...parseEuvd(fixture('enisa', 'no-cve.json')).records,
      ...parseGcveSightings(fixture('gcve', 'sightings.json')).records,
      ...parseProjectZeroRow({
        CVE: 'CVE-2026-134624',
        'Date Discovered': '2026-11-01',
        'Date Patched': '2026-11-10',
        Advisory: 'https://example.test/adv',
      }).records,
    ];
    expect(pzRows.length).toBeGreaterThan(1);
    const out = await link(records, f.deps);
    f.apply(out.rows);

    const signals = f.all('signals').filter((s) => s.vuln_key === 'CVE-2026-134624');
    expect(signals.map((s) => `${s.source}:${s.kind}`).sort()).toEqual([
      'enisa:exploited_wild',
      'gcve:exploited_wild',
      'gcve:poc',
      'project-zero:exploited_wild',
    ]);
    expect(f.all('vulns').find((v) => v.key === 'CVE-2026-134624')?.kev_added ?? null).toBeNull();
    for (const v of f.all('vulns')) expect(v.kev_added ?? null).toBeNull();

    const adv = f.all('advisories').find((a) => a.source === 'enisa' && a.source_id === 'EUVD-2026-132805');
    expect(adv).toMatchObject({ vuln_key: 'CVE-2026-134624' });

    const euvdVuln = f.all('vulns').find((v) => v.key === 'EUVD-2026-900001');
    expect(euvdVuln).toMatchObject({ kind: 'euvd' });
    // The parser gives the advisory no CVE; the linker hangs it on the EUVD hub.
    expect(f.all('advisories').find((a) => a.source_id === 'EUVD-2026-900001')?.vuln_key).toBe(
      'EUVD-2026-900001',
    );

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
