import { expect, it } from 'vitest';
import { fixture } from './fixtures';

it('reads a fixture file as text', () => {
  expect(JSON.parse(fixture('cisa-kev', 'sample.json')).catalogVersion).toBe('2025.05.05');
  expect(() => fixture('cisa-kev', 'missing.json')).toThrow('no fixture');
});
