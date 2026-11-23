import { describe, expect, it } from 'vitest';
import { APPEARANCE_VALUES, clerkAppearance } from '../app/lib/clerk-appearance';
import { readWeb } from './read-app';

const tokens = readWeb('app/styles/tokens.css');
const light = tokens.slice(0, tokens.indexOf('@media'));
const token = (name: string) =>
  new RegExp(`--${name}:\\s*([^;]+);`, 'i').exec(light)?.[1]?.trim().toLowerCase();

describe('Clerk appearance', () => {
  it('uses the colours, radius and font of tokens.css', () => {
    expect(APPEARANCE_VALUES.ink.toLowerCase()).toBe(token('ink'));
    expect(APPEARANCE_VALUES.canvas.toLowerCase()).toBe(token('canvas'));
    expect(APPEARANCE_VALUES.accent.toLowerCase()).toBe(token('accent'));
    expect(APPEARANCE_VALUES.radius).toBe(token('radius-md'));
    expect(APPEARANCE_VALUES.font).toContain('Geist');
    expect(token('font-text')).toContain('geist variable');
  });

  it('feeds those values to Clerk', () => {
    expect(clerkAppearance.variables).toMatchObject({
      colorPrimary: APPEARANCE_VALUES.accent,
      colorText: APPEARANCE_VALUES.ink,
      colorBackground: APPEARANCE_VALUES.canvas,
      borderRadius: APPEARANCE_VALUES.radius,
    });
  });
});
