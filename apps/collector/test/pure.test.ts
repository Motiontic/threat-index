import { NotImplementedError } from '@ti/core/errors';
import { describe, expect, it } from 'vitest';
import { MAX_STEPS_PER_RUN, parseJobMessage } from '../src/env';
import { describeError, isPermanent, PermanentError } from '../src/errors';
import { CADENCE_MS, isDue } from '../src/planner';

const RUN = '01KAH0000000000000000000AB';
const ok = { sourceId: 'osv', runId: RUN, step: 0, from: null };

describe('parseJobMessage', () => {
  it('accepts current messages', () => {
    expect(parseJobMessage(ok)).toEqual(ok);
    const from = { kind: 'commit', value: 'abc', etag: 'e' };
    expect(parseJobMessage({ ...ok, step: MAX_STEPS_PER_RUN, from })).toEqual({ ...ok, step: 500, from });
  });
  it('rejects old-format and malformed ones', () => {
    expect(parseJobMessage({ sourceId: 'osv', runId: RUN, step: 0 })).toBeNull(); // no `from`
    expect(parseJobMessage({ sourceId: 'osv', runId: 'mqlk3ab', step: 0, from: null })).toBeNull(); // old run id
    expect(parseJobMessage({ ...ok, step: 501 })).toBeNull();
    expect(parseJobMessage({ ...ok, step: -1 })).toBeNull();
    expect(parseJobMessage({ ...ok, step: 1.5 })).toBeNull();
    expect(parseJobMessage({ ...ok, from: { kind: 'nope', value: 'x' } })).toBeNull();
    expect(parseJobMessage({ ...ok, from: { kind: 'commit' } })).toBeNull();
    expect(parseJobMessage({ ...ok, sourceId: '' })).toBeNull();
    expect(parseJobMessage(null)).toBeNull();
    expect(parseJobMessage('x')).toBeNull();
    expect(parseJobMessage([])).toBeNull();
  });
});

describe('isDue', () => {
  const at = new Date('2026-11-23T12:00:00Z');
  const ago = (ms: number) => new Date(at.getTime() - ms);
  it('uses the cadence less 30 minutes of slack', () => {
    expect(isDue('3h', null, at)).toBe(true);
    expect(isDue('3h', ago(3_600_000), at)).toBe(false);
    expect(isDue('3h', ago(CADENCE_MS['3h'] - 30 * 60_000), at)).toBe(true);
    expect(isDue('3h', ago(CADENCE_MS['3h'] - 31 * 60_000), at)).toBe(false);
    expect(isDue('quarterly', ago(CADENCE_MS.monthly), at)).toBe(false);
  });
  it('has the specified cadences', () => {
    expect(CADENCE_MS['with-cve-list']).toBe(CADENCE_MS['3h']);
    expect(CADENCE_MS.daily).toBe(86_400_000);
    expect(CADENCE_MS.weekly).toBe(7 * 86_400_000);
    expect(CADENCE_MS.monthly).toBe(30 * 86_400_000);
    expect(CADENCE_MS.quarterly).toBe(91 * 86_400_000);
  });
});

describe('errors', () => {
  it('knows which errors are permanent', () => {
    expect(isPermanent(new PermanentError('x'))).toBe(true);
    expect(isPermanent(new NotImplementedError('x'))).toBe(true);
    expect(isPermanent(Object.assign(new Error('x'), { name: 'ZodError' }))).toBe(true);
    expect(isPermanent(new Error('x'))).toBe(false);
    expect(isPermanent('x')).toBe(false);
  });
  it('describeError strips query strings and caps length', () => {
    expect(describeError(new Error('GET https://a.example/p?key=S&b=1 failed'))).toBe(
      'Error: GET https://a.example/p failed',
    );
    expect(describeError(new Error('x'.repeat(900))).length).toBe(500);
  });
});
