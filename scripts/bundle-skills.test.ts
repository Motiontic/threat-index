import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs script
import * as bundler from './bundle-skills.mjs';

const { build, collect, checkChangelog, BundleError, shellProblemInLine, SHELL_WORDS } = bundler as {
  shellProblemInLine: (l: string) => string | null;
  SHELL_WORDS: string[];
  build: (dir: string) => Record<string, string>;
  collect: (dir: string) => {
    files: Record<string, string>;
    digests: Record<string, string>;
    bundleDigest: string;
  };
  checkChangelog: (dir: string, digest: string) => string;
  BundleError: new (...a: never[]) => Error;
};

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SKILLS = join(REPO, 'apps/mcp/skills');
const GOOD =
  '---\nname: demo\ndescription: A plain demo skill.\n---\n\n# Demo\n\nSee https://mti.motiontic.com/docs.\n';

const tmps: string[] = [];
afterEach(() => {
  for (const t of tmps.splice(0)) rmSync(t, { recursive: true, force: true });
});
function fixture(files: Record<string, string> = { 'demo/SKILL.md': GOOD }): string {
  const dir = mkdtempSync(join(tmpdir(), 'skills-'));
  tmps.push(dir);
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    writeFileSync(join(dir, p), text);
  }
  return dir;
}
const skill = (body: string) => fixture({ 'demo/SKILL.md': GOOD + body });
function rejects(dir: string, re: RegExp) {
  expect(() => collect(dir)).toThrow(re);
  try {
    collect(dir);
  } catch (e) {
    expect(e).toBeInstanceOf(BundleError);
  }
}

describe('bundler rules', () => {
  it('accepts a clean skill', () => {
    expect(Object.keys(collect(fixture()).files)).toEqual(['demo/SKILL.md']);
  });
  it('rejects a non-markdown file, naming it', () => {
    rejects(fixture({ 'demo/SKILL.md': GOOD, 'demo/run.sh': 'echo hi\n' }), /demo\/run\.sh: only markdown/);
  });
  it('rejects a symlink', () => {
    const dir = fixture();
    symlinkSync('/etc/hostname', join(dir, 'demo/link.md'));
    rejects(dir, /demo\/link\.md: symlinks/);
  });
  it.each([
    ['U+200B', '​'],
    ['U+202E', '‮'],
    ['U+E0041', '\u{E0041}'],
    ['U+00AD', '­'],
    ['U+FEFF', '﻿'],
  ])('rejects %s', (_n, ch) => {
    rejects(skill(`word${ch}word\n`), /demo\/SKILL\.md: character/);
  });
  it('rejects a tab, a carriage return and a UTF-8 file with non-ASCII bytes', () => {
    rejects(skill('a\tb\n'), /character U\+0009/);
    rejects(skill('a\r\n'), /character U\+000D/);
    rejects(skill('café\n'), /character/);
  });
  it('rejects an HTML comment and any "<"', () => {
    rejects(skill('<!-- hi -->\n'), /"<"/);
    rejects(skill('a < b\n'), /"<"/);
  });
  it('rejects links to another host, and www', () => {
    rejects(skill('[x](https://example.com/a)\n'), /links must go to/);
    rejects(skill('https://mti.motiontic.com.evil.test/a\n'), /links must go to/);
    rejects(skill('go to www.example.com\n'), /links must go to/);
    rejects(skill('ftp://mti.motiontic.com/\n'), /links must go to/);
  });
  it('rejects fences, indented code and shell-looking lines', () => {
    rejects(skill('```\nx\n```\n'), /code fences/);
    rejects(skill('~~~\nx\n'), /code fences/);
    rejects(skill('    indented\n'), /indented/);
    for (const l of [
      '$ ls',
      'npm i x',
      '- pnpm add x',
      '1. curl x',
      '> sudo x',
      '* pip x',
      'go get x',
      'cargo add x',
    ])
      rejects(skill(`${l}\n`), /shell command/);
  });
  it('rejects the word install outside safe-install', () => {
    rejects(skill('Then install it.\n'), /install/);
  });
  it('rejects an allowed-tools key, extra keys and a bad name or description', () => {
    const fm = (extra: string) => `---\nname: demo\ndescription: Fine.\n${extra}---\n\nbody\n`;
    rejects(fixture({ 'demo/SKILL.md': fm('allowed-tools: Bash\n') }), /exactly name and description/);
    rejects(
      fixture({ 'demo/SKILL.md': fm('disable-model-invocation: true\n') }),
      /exactly name and description/,
    );
    rejects(fixture({ 'demo/SKILL.md': GOOD.replace('name: demo', 'name: other') }), /must equal the folder/);
    for (const d of ['has: colon', 'has # hash', 'has "quote"', "has 'quote'"])
      rejects(fixture({ 'demo/SKILL.md': GOOD.replace('A plain demo skill.', d) }), /plain line/);
    rejects(fixture({ 'demo/SKILL.md': '# no frontmatter\n' }), /frontmatter/);
  });
  it('rejects bad path segments and a nested SKILL.md', () => {
    rejects(fixture({ 'demo/SKILL.md': GOOD, 'demo/References/a.md': 'x\n' }), /path segment "References"/);
    rejects(fixture({ 'demo/SKILL.md': GOOD, 'demo/_a.md': 'x\n' }), /path segment "_a\.md"/);
    rejects(fixture({ 'demo/SKILL.md': GOOD, 'demo/sub/SKILL.md': GOOD }), /SKILL\.md is only allowed/);
  });
  it.each([
    '[a]',
    '{a}',
    '| a',
    '> a',
    '! a',
    '& a',
    '* a',
    '- a',
    '? a',
    '% a',
    '@a',
    'true',
    'No',
    'null',
    'OFF',
  ])('rejects description %s', (d) => {
    rejects(fixture({ 'demo/SKILL.md': GOOD.replace('A plain demo skill.', d) }), /description must/);
  });
  it('rejects // \\ mailto javascript data and bad link targets', () => {
    for (const s of ['a // b', 'a \\ b', 'mailto:x', 'javascript:x', 'data:x'])
      rejects(skill(`${s}\n`), /links must go to/);
    rejects(skill('[x](../other.md)\n'), /link target/);
    rejects(skill('[x](/etc/passwd)\n'), /link target/);
    rejects(skill('[x]: ../other\n'), /link target/);
    expect(() => collect(skill('[x](references/a.md) [y](https://mti.motiontic.com/docs)\n'))).not.toThrow();
  });
  it('rejects shell commands case-insensitively, repeated markers and inline code spans', () => {
    for (const l of [
      'NPM i x',
      '- 1. > npx x',
      '+ git push',
      '2) Bash x',
      'Run `npm i x` now',
      'a `  docker run` b',
      '* `sh x`',
      'python x',
      'node x',
      'make x',
    ])
      rejects(skill(`${l}\n`), /shell command/);
  });
  it('rejects a missing skill release version rules', () => {
    const dir = fixture();
    const { bundleDigest } = collect(dir);
    const d2 = `sha256:${'1'.repeat(64)}`;
    writeFileSync(join(dir, 'CHANGELOG.md'), `## 1.0.0 - ${bundleDigest}\n\n## 1.0.0 - ${d2}\n`);
    expect(() => checkChangelog(dir, bundleDigest)).toThrow(/strictly increase/);
    writeFileSync(join(dir, 'CHANGELOG.md'), `## 0.9.0 - ${bundleDigest}\n\n## 1.0.0 - ${d2}\n`);
    expect(() => checkChangelog(dir, bundleDigest)).toThrow(/strictly increase/);
    writeFileSync(join(dir, 'CHANGELOG.md'), `## 2.0.0 - ${bundleDigest}\n\n## 1.0.0 - ${d2}\n`);
    expect(checkChangelog(dir, bundleDigest)).toBe('2.0.0');
    writeFileSync(join(dir, 'CHANGELOG.md'), `## draft\n\n## 1.0.0 - ${bundleDigest}\n`);
    expect(() => checkChangelog(dir, bundleDigest)).toThrow(/entry is not/);
  });
  it('rejects a skill with no SKILL.md', () => {
    rejects(fixture({ 'demo/SKILL.md': GOOD, 'other/x.md': 'x\n' }), /other: skill folder has no SKILL\.md/);
  });
  it('rejects a file over 100 KB and a skill over 400 KB', () => {
    const line = `${'a'.repeat(99)}\n`;
    rejects(skill(line.repeat(1100)), /over 102400 bytes/);
    const chunk = line.repeat(900); // ~90 KB each
    const files: Record<string, string> = { 'demo/SKILL.md': GOOD };
    for (let i = 0; i < 5; i++) files[`demo/references/r${i}.md`] = chunk;
    rejects(fixture(files), /demo: skill is over 409600 bytes/);
  });
  it('rejects a missing, wrong or stale changelog entry', () => {
    const dir = fixture();
    const { bundleDigest } = collect(dir);
    expect(() => build(dir)).toThrow(/CHANGELOG\.md: missing.*sha256:/);
    writeFileSync(join(dir, 'CHANGELOG.md'), `## 1.0.0 - sha256:${'0'.repeat(64)}\n`);
    expect(() => build(dir)).toThrow(new RegExp(`bundle digest is ${bundleDigest}`));
    writeFileSync(join(dir, 'CHANGELOG.md'), `## 1.2.3 - ${bundleDigest}\n`);
    expect(checkChangelog(dir, bundleDigest)).toBe('1.2.3');
  });
});

describe('fresh bundle', () => {
  it('matches the committed generated file and plugin files exactly', () => {
    const out = build(SKILLS);
    for (const [p, text] of Object.entries(out)) {
      expect(readFileSync(join(REPO, p), 'utf8'), `${p} is stale: run pnpm skills:bundle`).toBe(text);
    }
    const onDisk: string[] = [];
    const walk = (d: string) => {
      for (const e of readdirSync(d, { withFileTypes: true })) {
        if (e.isDirectory()) walk(join(d, e.name));
        else onDisk.push(join(d, e.name).slice(REPO.length + 1));
      }
    };
    walk(join(REPO, 'plugins/mti'));
    expect(onDisk.sort()).toEqual(
      Object.keys(out)
        .filter((p) => p.startsWith('plugins/'))
        .sort(),
    );
  });
});

describe('real skills', () => {
  const { files } = collect(SKILLS);
  it('no line or inline code span starts a shell command, inside or outside code fences', () => {
    expect(SHELL_WORDS).toEqual(
      expect.arrayContaining(['npx', 'git', 'bash', 'sh', 'node', 'python', 'docker', 'brew', 'apt', 'make']),
    );
    for (const [p, text] of Object.entries(files))
      for (const line of text.split('\n')) expect(shellProblemInLine(line), `${p}: ${line}`).toBeNull();
  });
  it('has no fences, HTML or links outside MTI', () => {
    for (const [p, text] of Object.entries(files)) {
      expect(text, p).not.toMatch(/```|~~~|</);
      expect(text.split('https://mti.motiontic.com/').join(''), p).not.toMatch(/:\/\/|www\./);
    }
  });
  it('only mentions install in the skill name', () => {
    for (const [p, text] of Object.entries(files))
      expect(text.replace(/safe-install/g, ''), p).not.toMatch(/install/i);
  });
  it('mentions no tool outside mti_*', () => {
    for (const [p, text] of Object.entries(files)) {
      expect(text, p).not.toMatch(/mcp__|\b(Bash|WebFetch|WebSearch|NotebookEdit)\b/);
      for (const m of text.match(/\bmti_[a-z_]+/g) ?? [])
        expect(['mti_check_packages', 'mti_watch_add'], `${p}: ${m}`).toContain(m);
    }
  });
  it('are-we-affected forbids the credential files', () => {
    const t = files['are-we-affected/SKILL.md'] ?? '';
    for (const f of ['.npmrc', '.pypirc', '.netrc', 'pip.conf', '.yarnrc', '.env']) expect(t).toContain(f);
    expect(t).toMatch(/Never open/);
    expect(t).toMatch(/Never send purls/);
    expect(t).toMatch(/only names and versions are sent/);
    expect(t).toMatch(/at most 1,000 packages per call/i);
  });
  it('safe-install re-checks upgradeTo and reads no files', () => {
    const t = files['safe-install/SKILL.md'] ?? '';
    expect(t).toMatch(/call `mti_check_packages` again for that `upgradeTo`/);
    expect(t).toMatch(/Read no files/);
    expect(t).toMatch(/Never guess a version/);
  });
  it('names ecosystems exactly as the tool enum does', () => {
    const t = files['are-we-affected/references/lockfiles.md'] ?? '';
    expect(t).not.toMatch(/SwiftPM/);
    for (const e of [
      'npm',
      'PyPI',
      'Go',
      'Maven',
      'crates.io',
      'RubyGems',
      'NuGet',
      'Packagist',
      'Hex',
      'Pub',
      'SwiftURL',
      'GitHub Actions',
    ])
      expect(t).toContain(e);
    for (const row of [
      '`golang` | Go',
      '`cargo` | crates.io',
      '`swift` | SwiftURL',
      '`github` | GitHub Actions',
      '`composer` | Packagist',
    ])
      expect(t).toContain(row);
    expect(t).toMatch(/always use `name` when present/);
    expect(t).toMatch(/pip-compile/);
    expect(t).toMatch(/as written/);
  });
  it('are-we-affected waits for consent, pages, and handles rejects', () => {
    const t = files['are-we-affected/SKILL.md'] ?? '';
    expect(t).toMatch(/wait for the user to agree\. Send nothing before that/);
    expect(t).toMatch(/internal or private package names/);
    expect(t).toMatch(/`truncated` is true.*`nextCursor`/);
    expect(t).toMatch(/`rejected`/);
    expect(t).toMatch(/split that batch by ecosystem/);
    expect(t).toMatch(/different name as a replacement/);
  });
  it('safe-install says when no safe version is known', () => {
    expect(files['safe-install/SKILL.md']).toMatch(/no safe version is known from MTI/);
  });
  it('lockfiles.md covers every format in the spec', () => {
    const t = files['are-we-affected/references/lockfiles.md'] ?? '';
    for (const f of [
      'package-lock.json',
      'npm-shrinkwrap.json',
      'pnpm-lock.yaml',
      'yarn.lock',
      'bun.lock',
      'requirements',
      'poetry.lock',
      'uv.lock',
      'Pipfile.lock',
      'pdm.lock',
      'go.sum',
      'Cargo.lock',
      'Gemfile.lock',
      'composer.lock',
      'packages.lock.json',
      'gradle.lockfile',
      'mix.lock',
      'pubspec.lock',
      'Package.resolved',
      'CycloneDX',
      'SPDX',
    ])
      expect(t, f).toContain(f);
  });
});

describe('plugin', () => {
  const p = (f: string) => join(REPO, 'plugins/mti', f);
  it('has parseable manifests with the production URL', () => {
    const plugin = JSON.parse(readFileSync(p('.claude-plugin/plugin.json'), 'utf8'));
    expect(plugin.name).toBe('mti');
    expect(plugin.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(readFileSync(p('.mcp.json'), 'utf8')).toBe(
      '{"mcpServers":{"mti":{"type":"http","url":"https://mti.motiontic.com/mcp"}}}',
    );
  });
  it('copies the skill bytes', () => {
    for (const [path] of Object.entries(collect(SKILLS).files))
      expect(readFileSync(p(`skills/${path}`))).toEqual(readFileSync(join(SKILLS, path)));
  });
});
