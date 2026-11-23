// Clerk's look, matched to tokens.css (a test compares these values with it). Geist, ink on canvas, one accent.
// Clerk takes literal colours, so this is the one file outside tokens.css that holds them.
export const APPEARANCE_VALUES = {
  ink: '#121212',
  canvas: '#FAFAF8',
  accent: '#EF7D45',
  radius: '10px',
  font: '"Geist Variable", ui-sans-serif, system-ui, sans-serif',
} as const;

export const clerkAppearance = {
  variables: {
    colorPrimary: APPEARANCE_VALUES.accent,
    colorText: APPEARANCE_VALUES.ink,
    colorBackground: APPEARANCE_VALUES.canvas,
    colorForeground: APPEARANCE_VALUES.ink,
    borderRadius: APPEARANCE_VALUES.radius,
    fontFamily: APPEARANCE_VALUES.font,
  },
};
