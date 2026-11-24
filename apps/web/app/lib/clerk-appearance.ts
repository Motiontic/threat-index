// Clerk's look, matched to tokens.css (a test checks every token named here exists there). Colours are the
// site's CSS variables, not literals, so Clerk's forms switch between light and dark with the rest of the
// page. A literal light palette here once met Clerk's own dark-mode defaults for inputs and buttons and left
// white text on white and dark placeholders on dark fields.
export const APPEARANCE_TOKENS = {
  colorForeground: 'ink',
  colorMutedForeground: 'ink-3',
  colorBackground: 'paper',
  colorInput: 'canvas',
  colorInputForeground: 'ink',
  colorNeutral: 'ink',
  colorBorder: 'line-2',
  colorModalBackdrop: 'canvas-90',
} as const;

export const APPEARANCE_VALUES = {
  // Clerk builds the button's hover and pressed shades from the primary colour, which it cannot do from a CSS
  // variable (the button came out grey), so the accent is a literal: the light-mode token, used in both modes.
  accent: '#EF7D45',
  // Text on the accent button: the light-mode ink, which reads on the accent in both modes.
  onAccent: '#121212',
  radius: '10px',
  font: '"Geist Variable", ui-sans-serif, system-ui, sans-serif',
} as const;

const vars = Object.fromEntries(
  Object.entries(APPEARANCE_TOKENS).map(([k, token]) => [k, `var(--${token})`]),
) as { [K in keyof typeof APPEARANCE_TOKENS]: string };

export const clerkAppearance = {
  variables: {
    ...vars,
    colorPrimary: APPEARANCE_VALUES.accent,
    colorRing: APPEARANCE_VALUES.accent,
    colorPrimaryForeground: APPEARANCE_VALUES.onAccent,
    borderRadius: APPEARANCE_VALUES.radius,
    fontFamily: APPEARANCE_VALUES.font,
  },
};
