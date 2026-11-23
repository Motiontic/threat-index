import { describe, expect, it } from 'vitest';
import { isAdmin, parseAdminIds } from './ops';

describe('parseAdminIds', () => {
  it('returns nothing for empty input', () => {
    expect(parseAdminIds()).toEqual([]);
    expect(parseAdminIds('')).toEqual([]);
    expect(parseAdminIds(' , ')).toEqual([]);
  });
  it('trims and keeps valid ids, dropping the rest', () => {
    expect(parseAdminIds(' user_abc123 , nope, user_, user_a-b, org_x,user_Z9')).toEqual([
      'user_abc123',
      'user_Z9',
    ]);
  });
  it('drops ids over 64 characters and keeps at most 20', () => {
    expect(parseAdminIds(`user_${'a'.repeat(65)}`)).toEqual([]);
    const many = Array.from({ length: 30 }, (_, i) => `user_${i}`).join(',');
    expect(parseAdminIds(many)).toHaveLength(20);
  });
});

describe('isAdmin', () => {
  it('matches only a listed user', () => {
    expect(isAdmin(['user_a'], 'user_a')).toBe(true);
    expect(isAdmin(['user_a'], 'user_b')).toBe(false);
  });
  it('is false with no list or no user', () => {
    expect(isAdmin([], 'user_a')).toBe(false);
    expect(isAdmin(['user_a'], undefined)).toBe(false);
    expect(isAdmin(['user_a'], '')).toBe(false);
  });
});
