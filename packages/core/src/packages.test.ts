import { describe, expect, it } from 'vitest';
import {
  CheckEntrySchema,
  CheckRequestSchema,
  canonicalEcosystem,
  ECOSYSTEMS,
  MAX_CHECK_PACKAGES,
  normaliseName,
  type PriorityInput,
  parsePurl,
  rankPriority,
} from './packages';

describe('canonicalEcosystem', () => {
  it('maps aliases and purl types to the canonical name', () => {
    expect(canonicalEcosystem('pypi')).toBe('PyPI');
    expect(canonicalEcosystem('cargo')).toBe('crates.io');
    expect(canonicalEcosystem('golang')).toBe('Go');
    expect(canonicalEcosystem('gem')).toBe('RubyGems');
    expect(canonicalEcosystem('composer')).toBe('Packagist');
    expect(canonicalEcosystem('NPM')).toBe('npm');
    expect(canonicalEcosystem('github actions')).toBe('GitHub Actions');
  });
  it('knows every canonical name from its lower-case form', () => {
    for (const e of ECOSYSTEMS) expect(canonicalEcosystem(e.toLowerCase())).toBe(e);
  });
  it('returns null for deb (needs a distro), unknown names and prototype keys', () => {
    expect(canonicalEcosystem('deb')).toBeNull();
    expect(canonicalEcosystem('nope')).toBeNull();
    expect(canonicalEcosystem('toString')).toBeNull();
    expect(canonicalEcosystem('__proto__')).toBeNull();
  });
});

describe('normaliseName', () => {
  it('lower-cases npm names and keeps the scope', () => {
    expect(normaliseName('npm', 'Lodash')).toBe('lodash');
    expect(normaliseName('npm', '@Angular/Core')).toBe('@angular/core');
    expect(normaliseName('npm', '@angular')).toBeNull();
    expect(normaliseName('npm', 'a/b')).toBeNull();
  });
  it('applies PEP 503 to PyPI', () => {
    expect(normaliseName('PyPI', 'Foo_Bar.baz')).toBe('foo-bar-baz');
    expect(normaliseName('PyPI', 'a--b__c')).toBe('a-b-c');
    expect(normaliseName('PyPI', '-bad')).toBeNull();
  });
  it('lower-cases crates.io and turns _ into -', () => {
    expect(normaliseName('crates.io', 'Serde_JSON')).toBe('serde-json');
  });
  it('lower-cases NuGet, Packagist, Hex and Pub', () => {
    expect(normaliseName('NuGet', 'Newtonsoft.Json')).toBe('newtonsoft.json');
    expect(normaliseName('Packagist', 'Symfony/Console')).toBe('symfony/console');
    expect(normaliseName('Hex', 'Phoenix')).toBe('phoenix');
    expect(normaliseName('Pub', 'Http')).toBe('http');
  });
  it('leaves Go, RubyGems and SwiftURL alone, and needs group:artifact for Maven', () => {
    expect(normaliseName('Go', 'github.com/Foo/Bar')).toBe('github.com/Foo/Bar');
    expect(normaliseName('RubyGems', 'Rails')).toBe('Rails');
    expect(normaliseName('SwiftURL', 'github.com/Apple/swift-nio')).toBe('github.com/Apple/swift-nio');
    expect(normaliseName('Maven', 'org.Apache:Commons')).toBe('org.Apache:Commons');
    expect(normaliseName('Maven', 'noartifact')).toBeNull();
    expect(normaliseName('Maven', 'a:b:c')).toBeNull();
  });
  it('rejects empty, spaced, control-character and over-long names', () => {
    for (const e of ECOSYSTEMS) {
      expect(normaliseName(e, '')).toBeNull();
      expect(normaliseName(e, 'a b')).toBeNull();
      expect(normaliseName(e, 'a\nb')).toBeNull();
      expect(normaliseName(e, 'a'.repeat(301))).toBeNull();
    }
  });
});

describe('parsePurl', () => {
  it('parses a plain purl', () => {
    expect(parsePurl('pkg:npm/lodash@4.17.20')).toEqual({
      ok: true,
      ref: { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },
    });
  });
  it('handles scopes, encoded or not', () => {
    for (const p of ['pkg:npm/%40angular/core@16.0.0', 'pkg:npm/@angular/core@16.0.0'])
      expect(parsePurl(p)).toEqual({
        ok: true,
        ref: { ecosystem: 'npm', name: '@angular/core', version: '16.0.0' },
      });
  });
  it('joins a Maven namespace with ":" and normalises PyPI', () => {
    expect(parsePurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1')).toEqual({
      ok: true,
      ref: { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1' },
    });
    expect(parsePurl('pkg:pypi/Django_Rest@3.0')).toEqual({
      ok: true,
      ref: { ecosystem: 'PyPI', name: 'django-rest', version: '3.0' },
    });
    expect(parsePurl('pkg:golang/github.com/gin-gonic/gin@v1.9.0')).toEqual({
      ok: true,
      ref: { ecosystem: 'Go', name: 'github.com/gin-gonic/gin', version: 'v1.9.0' },
    });
  });
  it('drops qualifiers and subpaths: they are never returned', () => {
    const r = parsePurl(
      'pkg:npm/foo@1.0.0?repository_url=https://evil.example/&download_url=https://evil.example/x.tgz#sub/path',
    );
    expect(r).toEqual({ ok: true, ref: { ecosystem: 'npm', name: 'foo', version: '1.0.0' } });
    expect(JSON.stringify(r)).not.toContain('evil');
  });
  it('uses the distro qualifier to resolve deb', () => {
    expect(parsePurl('pkg:deb/openssl@3.0.11?distro=debian-12')).toMatchObject({
      ok: true,
      ref: { ecosystem: 'Debian' },
    });
    expect(parsePurl('pkg:deb/openssl@3.0.11?arch=amd64&distro=ubuntu-22.04')).toMatchObject({
      ok: true,
      ref: { ecosystem: 'Ubuntu' },
    });
    expect(parsePurl('pkg:deb/openssl@3.0.11')).toEqual({ ok: false, reason: 'bad_ecosystem' });
  });
  it('rejects with a reason code and never echoes the input', () => {
    expect(parsePurl('npm/lodash@1')).toEqual({ ok: false, reason: 'bad_purl' });
    expect(parsePurl('pkg:npm')).toEqual({ ok: false, reason: 'bad_purl' });
    expect(parsePurl('pkg:npm/lodash')).toEqual({ ok: false, reason: 'bad_version' });
    expect(parsePurl('pkg:npm/lodash@')).toEqual({ ok: false, reason: 'bad_version' });
    expect(parsePurl('pkg:nope/lodash@1')).toEqual({ ok: false, reason: 'bad_ecosystem' });
    expect(parsePurl('pkg:npm/%E0%A4%A@1')).toEqual({ ok: false, reason: 'bad_purl' });
    expect(parsePurl('pkg:npm/a%20b@1')).toEqual({ ok: false, reason: 'bad_name' });
    expect(parsePurl(`pkg:npm/a@${'1'.repeat(200)}`)).toEqual({ ok: false, reason: 'bad_version' });
    expect(parsePurl(`pkg:npm/${'a'.repeat(2000)}@1`)).toEqual({ ok: false, reason: 'bad_purl' });
  });
});

describe('rankPriority', () => {
  const base: PriorityInput = {
    exploitedWild: false,
    ransomware: false,
    malicious: false,
    publicExploit: false,
    poc: false,
    epss: null,
    cvss: null,
    severityLabel: null,
  };
  const rank = (o: Partial<PriorityInput>) => rankPriority({ ...base, ...o });

  it('fix_now for exploited, ransomware or malicious, whatever else is true', () => {
    expect(rank({ exploitedWild: true })).toBe('fix_now');
    expect(rank({ ransomware: true })).toBe('fix_now');
    expect(rank({ malicious: true, cvss: 1 })).toBe('fix_now');
  });
  it('fix_soon for a public exploit, a PoC or EPSS >= 0.1', () => {
    expect(rank({ publicExploit: true })).toBe('fix_soon');
    expect(rank({ poc: true, cvss: 2 })).toBe('fix_soon');
    expect(rank({ epss: 0.1 })).toBe('fix_soon');
    expect(rank({ epss: 0.0999 })).toBe('note');
  });
  it('plan for CVSS >= 7, or a HIGH/CRITICAL label when there is no score', () => {
    expect(rank({ cvss: 7 })).toBe('plan');
    expect(rank({ cvss: 6.9 })).toBe('note');
    expect(rank({ severityLabel: 'HIGH' })).toBe('plan');
    expect(rank({ severityLabel: 'critical' })).toBe('plan');
    expect(rank({ severityLabel: 'MODERATE' })).toBe('note');
  });
  it('a score wins over the label', () => {
    expect(rank({ cvss: 3, severityLabel: 'CRITICAL' })).toBe('note');
  });
  it('note for everything else', () => {
    expect(rank({})).toBe('note');
  });
});

describe('check request schema', () => {
  it('accepts purl entries and ecosystem/name/version entries', () => {
    expect(CheckEntrySchema.safeParse({ purl: 'pkg:npm/a@1' }).success).toBe(true);
    expect(CheckEntrySchema.safeParse({ ecosystem: 'npm', name: 'a', version: '1' }).success).toBe(true);
    expect(CheckEntrySchema.safeParse({ name: 'a' }).success).toBe(false);
  });
  it('limits the list to 1..MAX_CHECK_PACKAGES, entries unparsed', () => {
    expect(CheckRequestSchema.safeParse({ packages: [] }).success).toBe(false);
    expect(CheckRequestSchema.safeParse({ packages: [{ purl: 'x' }, 7] }).success).toBe(true);
    expect(CheckRequestSchema.safeParse({ packages: new Array(MAX_CHECK_PACKAGES + 1).fill(1) }).success).toBe(
      false,
    );
  });
});
