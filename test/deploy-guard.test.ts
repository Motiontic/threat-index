import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs script without types
import { DEPLOY_ORDER, productionGuard } from '../scripts/deploy.mjs';

// Real git, in a throwaway "origin" and clone, never this repository. Nothing is pushed: the clone is made
// from a local origin, and a "pushed" branch is simulated with a remote-tracking ref.
const base = mkdtempSync(join(tmpdir(), 'deploy-guard-'));
afterAll(() => rmSync(base, { recursive: true, force: true }));

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: 't',
  GIT_AUTHOR_EMAIL: 't@example.test',
  GIT_COMMITTER_NAME: 't',
  GIT_COMMITTER_EMAIL: 't@example.test',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_SYSTEM: '/dev/null',
};
const git = (cwd: string, ...args: string[]) =>
  execFileSync('git', args, { cwd, env: GIT_ENV, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

let clone: string;
let n = 0;
beforeEach(() => {
  const dir = join(base, `case${n++}`);
  const origin = join(dir, 'origin');
  clone = join(dir, 'clone');
  mkdirSync(origin, { recursive: true });
  execFileSync('git', ['init', '-b', 'main', origin], { env: GIT_ENV, stdio: 'ignore' });
  writeFileSync(join(origin, 'a.txt'), 'a');
  git(origin, 'add', '.');
  git(origin, 'commit', '-m', 'first');
  execFileSync('git', ['clone', origin, clone], { env: GIT_ENV, stdio: 'ignore' });
});

describe('productionGuard', () => {
  it('lets a clean checkout of pushed origin/main through', () => {
    expect(productionGuard(clone)).toEqual([]);
  });

  it('lets a detached checkout of a commit on main through (a tag deploy in CI)', () => {
    git(clone, 'tag', 'v1');
    git(clone, 'checkout', '--detach', 'v1');
    expect(productionGuard(clone)).toEqual([]);
  });

  it('refuses a modified file', () => {
    writeFileSync(join(clone, 'a.txt'), 'changed');
    expect(productionGuard(clone).join('\n')).toMatch(/working tree is not clean/);
  });

  it('refuses an untracked file', () => {
    writeFileSync(join(clone, 'new.txt'), 'x');
    expect(productionGuard(clone).join('\n')).toMatch(/working tree is not clean/);
  });

  it('refuses an unpushed commit, and says it is not on origin/main', () => {
    writeFileSync(join(clone, 'b.txt'), 'b');
    git(clone, 'add', '.');
    git(clone, 'commit', '-m', 'local only');
    const text = productionGuard(clone).join('\n');
    expect(text).toMatch(/not on origin\/main/);
    expect(text).toMatch(/1 commit\(s\) on HEAD are not pushed/);
  });

  it('refuses a pushed feature branch that is not merged to main', () => {
    git(clone, 'checkout', '-b', 'feat/x');
    writeFileSync(join(clone, 'b.txt'), 'b');
    git(clone, 'add', '.');
    git(clone, 'commit', '-m', 'feature');
    git(clone, 'update-ref', 'refs/remotes/origin/feat/x', 'HEAD'); // as if pushed
    const problems = productionGuard(clone);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/HEAD is not on origin\/main/);
  });

  it('refuses when origin/main is unknown', () => {
    git(clone, 'update-ref', '-d', 'refs/remotes/origin/main');
    expect(productionGuard(clone).join('\n')).toMatch(/origin\/main is not known/);
  });

  it('reports every problem at once', () => {
    writeFileSync(join(clone, 'b.txt'), 'b');
    git(clone, 'add', '.');
    git(clone, 'commit', '-m', 'local only');
    writeFileSync(join(clone, 'a.txt'), 'changed');
    expect(productionGuard(clone)).toHaveLength(3);
  });

  it('refuses a directory that is not a git repository', () => {
    expect(productionGuard(base).join('\n')).toMatch(/could not read the git state/);
  });
});

describe('deploy order', () => {
  it('deploys mcp after the API it calls and before the web Worker that forwards to it', () => {
    expect(DEPLOY_ORDER).toEqual(['loader', 'notify', 'api', 'collector', 'mcp', 'web']);
  });
});
