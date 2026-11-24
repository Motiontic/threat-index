// Keyboard rules shared by the themed dropdown, the quick-search palette and the More menu. Pure, so they
// can be tested without a browser.

export type ListKey = 'ArrowDown' | 'ArrowUp' | 'Home' | 'End';

/** The index to move to for a key press in a list of `length` items. Arrows wrap; -1 means "none yet". */
export function moveIndex(key: ListKey, index: number, length: number): number {
  if (length <= 0) return -1;
  if (key === 'Home') return 0;
  if (key === 'End') return length - 1;
  if (key === 'ArrowDown') return index < 0 ? 0 : (index + 1) % length;
  return index <= 0 ? length - 1 : index - 1;
}

export const isListKey = (key: string): key is ListKey =>
  key === 'ArrowDown' || key === 'ArrowUp' || key === 'Home' || key === 'End';

export interface DisclosureState {
  open: boolean;
  /** Where focus goes on the next close; set by the key or click that closed it. */
  returnFocus: boolean;
}

export type DisclosureEvent = 'toggle' | 'escape' | 'outside' | 'navigate';

/**
 * One disclosure (More menu, palette, dropdown): toggles on its button, closes on Escape, an outside click
 * and navigation. Escape returns focus to the button; an outside click or navigation leaves focus where the
 * visitor put it.
 */
export function disclosure(state: DisclosureState, event: DisclosureEvent): DisclosureState {
  if (event === 'toggle') return { open: !state.open, returnFocus: state.open };
  if (!state.open) return state;
  return { open: false, returnFocus: event === 'escape' };
}

/** The next element to focus when Tab is pressed inside a trapped dialog, or null to let the browser decide. */
export function trapTarget<T>(items: T[], active: T | null, shift: boolean): T | null {
  if (items.length === 0) return null;
  const first = items[0] as T;
  const last = items[items.length - 1] as T;
  if (active === null || !items.includes(active)) return shift ? last : first;
  if (shift && active === first) return last;
  if (!shift && active === last) return first;
  return null;
}
