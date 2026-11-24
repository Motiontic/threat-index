import { describe, expect, it } from 'vitest';
import { APPEARANCE_TOKENS, APPEARANCE_VALUES, clerkAppearance } from '../app/lib/clerk-appearance';
import { readWeb } from './read-app';

const tokens = readWeb('app/styles/tokens.css');
const light = tokens.slice(0, tokens.indexOf('@media'));
const dark = tokens.slice(tokens.indexOf('@media'));
const token = (css: string, name: string) =>
  new RegExp(`--${name}:\\s*([^;]+);`, 'i').exec(css)?.[1]?.trim().toLowerCase();

describe('Clerk appearance', () => {
  it('names only tokens that tokens.css defines for both light and dark', () => {
    for (const name of Object.values(APPEARANCE_TOKENS)) {
      expect(token(light, name), `light --${name}`).toBeTruthy();
      expect(token(dark, name), `dark --${name}`).toBeTruthy();
    }
  });

  it('feeds Clerk the CSS variables, so its forms follow the page theme', () => {
    for (const [key, name] of Object.entries(APPEARANCE_TOKENS)) {
      expect(clerkAppearance.variables[key as keyof typeof APPEARANCE_TOKENS]).toBe(`var(--${name})`);
    }
    // Every colour Clerk draws text or a field with is set, so none falls back to Clerk's own theme.
    for (const key of [
      'colorForeground',
      'colorBackground',
      'colorInput',
      'colorInputForeground',
      'colorNeutral',
    ]) {
      expect(clerkAppearance.variables).toHaveProperty(key);
    }
  });

  it('keeps the accent, radius, font and text on the accent from tokens.css', () => {
    expect(APPEARANCE_VALUES.radius).toBe(token(light, 'radius-md'));
    expect(APPEARANCE_VALUES.onAccent.toLowerCase()).toBe(token(light, 'ink'));
    expect(APPEARANCE_VALUES.accent.toLowerCase()).toBe(token(light, 'accent'));
    expect(clerkAppearance.variables.colorPrimary).toBe(APPEARANCE_VALUES.accent);
    expect(APPEARANCE_VALUES.font).toContain('Geist');
    expect(token(light, 'font-text')).toContain('geist variable');
    expect(clerkAppearance.variables.colorPrimaryForeground).toBe(APPEARANCE_VALUES.onAccent);
  });
});
