// Excluded from tsc (no Node types here); vitest runs it. Writes sample emails when NOTIFY_PROOF_DIR is set.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { it } from 'vitest';
import type { Change } from '../src/collect';
import { type RenderItem, renderEmail } from '../src/render';

const ch = (kind: string, o: Partial<Change> = {}): Change => ({
  id: 'c1',
  entity_key: 'CVE-2026-0001',
  kind,
  old: null,
  new: null,
  at: '2026-11-23T01:00:00Z',
  source: 'osv',
  ...o,
});
const item = (o: Partial<RenderItem> & { change?: Change } = {}): RenderItem => ({
  change: ch('newly_exploited', { new: '2026-11-20' }),
  title: 'Acme Gateway RCE',
  company: false,
  group: null,
  ...o,
});
const base = { appBase: 'https://app.example', unsubscribeUrl: 'https://api.example/unsubscribe?t=tok' };

it('writes sample emails to NOTIFY_PROOF_DIR when set', () => {
  const dir = process.env.NOTIFY_PROOF_DIR;
  if (!dir) return;
  mkdirSync(dir, { recursive: true });
  const instant = renderEmail({
    ...base,
    kind: 'instant',
    items: [
      item({ title: 'Acme Gateway remote code execution' }),
      item({
        title: 'Initech VPN auth bypass',
        change: ch('public_exploit', { entity_key: 'CVE-2026-0002', source: 'cve-list' }),
      }),
    ],
  });
  const daily = renderEmail({
    ...base,
    kind: 'daily',
    items: [
      item({ title: 'Acme Gateway remote code execution' }),
      item({
        title: 'Initech VPN auth bypass',
        change: ch('epss_band', { entity_key: 'CVE-2026-0002', old: '0.02', new: '0.41' }),
      }),
      item({
        title: 'Globex Corp',
        company: true,
        group: 'Breaches in energy',
        change: ch('breach_notice', { entity_key: 'globex', source: 'cve-list' }),
      }),
    ],
  });
  for (const [name, r] of [
    ['instant', instant],
    ['daily', daily],
  ] as const) {
    writeFileSync(join(dir, `${name}.txt`), `Subject: ${r.subject}\n\n${r.text}\n`);
    writeFileSync(join(dir, `${name}.html`), r.html);
  }
});
