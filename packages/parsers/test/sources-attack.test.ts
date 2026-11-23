import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { fetch as heavyFetch } from '../../patterns/src/heavy';
import { makeCtx, ranged, route } from '../../patterns/test/helpers';
import { SOURCE_BY_ID } from '../../sources/src/registry';
import { loadParser } from '../src/load';

const get = (id: string) => {
  const s = SOURCE_BY_ID.get(id);
  if (!s) throw new Error(`no source ${id}`);
  return s;
};

const ATTACK_URL =
  'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';
const ATLAS_URL = 'https://github.com/mitre-atlas/atlas-data/releases/latest/download/stix-atlas.json';
const MANIFEST_URL = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml';

describe('sources wired to the ATT&CK parsers', () => {
  it('mitre-attack', async () => {
    const s = get('mitre-attack');
    expect(s.parser).toBe('stix');
    expect(s.pull).toEqual({
      heavy: {
        url: ATTACK_URL,
        version: { url: ATTACK_URL, pattern: '"x_mitre_version":\\s*"([\\d.]+)"', bytes: 2048 },
      },
      jobKind: 'first-load',
    });
    expect(typeof (await loadParser('stix')).parse).toBe('function');
  });

  it('mitre-atlas', () => {
    const s = get('mitre-atlas');
    expect(s.parser).toBe('stix');
    expect(s.pull).toEqual({
      heavy: {
        url: ATLAS_URL,
        version: { url: MANIFEST_URL, pattern: "release: '([\\d.]+)'", bytes: 256 },
      },
      jobKind: 'first-load',
    });
  });

  it('openssf-malicious-packages', async () => {
    const s = get('openssf-malicious-packages');
    expect(s.parser).toBe('osv-malicious');
    expect(s.pull).toEqual({
      git: {
        repo: 'ossf/malicious-packages',
        branch: 'main',
        include: ['osv/malicious/**/*.json', 'osv/withdrawn/**/*.json'],
      },
    });
    expect(s).toMatchObject({
      pattern: 'git',
      cadence: '3h',
      licence: 'on',
      credit: 'Source: OpenSSF Malicious Packages (Apache-2.0)',
    });
    expect(typeof (await loadParser('osv-malicious')).parse).toBe('function');
  });

  it.each([
    ['mitre-attack', ATTACK_URL, ATTACK_URL, fixture('mitre-attack', 'pattern-version.json'), '20.1'],
    ['mitre-atlas', ATLAS_URL, MANIFEST_URL, fixture('mitre-atlas', 'pattern-manifest.yaml'), '2026.10'],
  ])(
    'heavy fetch of %s hands off a first-load job, and is unchanged at the same version',
    async (id, url, versionUrl, body, version) => {
      const source = get(id);
      const routes = [route(versionUrl, ranged(body))];
      const first = await heavyFetch(makeCtx({ source, routes }).ctx);
      expect(first).toMatchObject({
        nextCursor: { kind: 'version', value: version },
        heavy: { kind: 'first-load', url },
      });
      const same = await heavyFetch(
        makeCtx({ source, routes, cursor: { kind: 'version', value: version } }).ctx,
      );
      expect(same.heavy).toBeUndefined();
    },
  );
});
