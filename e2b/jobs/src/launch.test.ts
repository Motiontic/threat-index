import { describe, expect, it } from 'vitest';
import { describeExit, supervise } from './launch.ts';
import { fakeApi, JOB_ID } from './test-support.ts';
import type { Job } from './types.ts';

const job: Job = { id: JOB_ID, kind: 'echo', apiBase: 'https://api.test', hmac: 'secret-job-key' };
const node = (script: string, env: NodeJS.ProcessEnv = {}) => ({
  command: process.execPath,
  args: ['-e', script],
  env: { ...process.env, ...env },
  log: () => {},
});

describe('supervise', () => {
  it('a job process that exits non-zero without reporting ends failed, with a reason', async () => {
    const api = fakeApi();
    const code = await supervise(job, { api, ...node('process.exit(3)') });
    expect(code).toBe(3);
    expect(api.completed).toEqual([{ ok: false, error: 'job process exited with code 3' }]);
  });

  it('a job process killed by a signal ends failed', async () => {
    const api = fakeApi();
    const code = await supervise(job, { api, ...node("process.kill(process.pid, 'SIGKILL')") });
    expect(code).toBe(1);
    expect(api.completed).toEqual([{ ok: false, error: 'job process killed by SIGKILL' }]);
  });

  it('a real out-of-memory abort under a small heap is reported as such', async () => {
    const api = fakeApi();
    const script = 'const a=[];for(;;)a.push(new Array(1e5).fill(Math.random()))';
    const o = node(script);
    const code = await supervise(job, { api, ...o, args: ['--max-old-space-size=48', ...o.args] });
    expect(code).not.toBe(0);
    expect(api.completed).toHaveLength(1);
    expect((api.completed[0] as { error: string }).error).toMatch(/\(out of memory\)$/);
  }, 60_000);

  it('a clean exit reports nothing itself', async () => {
    const api = fakeApi();
    expect(await supervise(job, { api, ...node('0') })).toBe(0);
    expect(api.completed).toEqual([]);
  });

  it('a command that cannot start ends failed', async () => {
    const api = fakeApi();
    const code = await supervise(job, { api, command: '/no/such/node', args: [], env: {}, log: () => {} });
    expect(code).toBe(127);
    expect(api.completed).toHaveLength(1);
  });

  it('a failing report does not throw', async () => {
    const api = fakeApi();
    api.complete = async () => {
      throw new Error('api down');
    };
    expect(await supervise(job, { api, ...node('process.exit(2)') })).toBe(2);
  });

  it('the error never contains the job key', async () => {
    const api = fakeApi();
    const script = "console.error('boom secret-job-key');process.exit(1)";
    await supervise(job, { api, ...node(script, { JOB_JSON: JSON.stringify(job) }) });
    expect(JSON.stringify(api.completed)).not.toContain('secret-job-key');
  });

  it('describeExit', () => {
    expect(describeExit(134, null, 'FATAL ERROR: Reached heap limit Allocation failed')).toBe(
      'job process exited with code 134 (out of memory)',
    );
  });
});
