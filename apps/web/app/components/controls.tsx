// Controls drawn by MTI: the themed dropdown, the segmented control and the switch. Each one works as a
// plain form control before the page hydrates.
import { type KeyboardEvent, useCallback, useEffect, useId, useRef, useState } from 'react';
import { disclosure, isListKey, moveIndex } from '../lib/menu-nav';

export interface Option {
  value: string;
  label: string;
}

export function Chevron() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true" focusable="false">
      <path
        d="M3 5.25 7 9l4-3.75"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Tick() {
  return (
    <svg className="tick" width="14" height="14" viewBox="0 0 14 14" aria-hidden="true" focusable="false">
      <path
        d="m3 7.4 2.7 2.6L11 4.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/**
 * A `<select>` that becomes a themed dropdown after hydration. The server renders the native select (same
 * name, same value, works without JavaScript); once hydrated it stays in the form, hidden, as the field
 * that carries the value, and a button plus a listbox drive it.
 */
export function Select({
  id,
  name,
  label,
  options,
  defaultValue,
  onValueChange,
}: {
  id: string;
  name: string;
  /** The accessible name of the dropdown (the visible `<label htmlFor>` also names the native select). */
  label: string;
  options: Option[];
  defaultValue: string;
  onValueChange?: (value: string) => void;
}) {
  const [value, setValue] = useState(defaultValue);
  const [enhanced, setEnhanced] = useState(false);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const listId = useId();
  const selected = Math.max(
    0,
    options.findIndex((o) => o.value === value),
  );

  useEffect(() => setEnhanced(true), []);

  const close = useCallback((event: 'escape' | 'outside') => {
    const next = disclosure({ open: true, returnFocus: false }, event);
    setOpen(next.open);
    if (next.returnFocus) button.current?.focus();
  }, []);

  // An outside press closes the list.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      if (!root.current?.contains(e.target as Node)) close('outside');
    };
    document.addEventListener('pointerdown', onDown);
    return () => document.removeEventListener('pointerdown', onDown);
  }, [open, close]);

  // Opening puts focus on the chosen option; moving the active option moves focus with it.
  useEffect(() => {
    if (open && active >= 0) list.current?.querySelectorAll<HTMLElement>('[role="option"]')[active]?.focus();
  }, [open, active]);

  const choose = (index: number) => {
    const o = options[index];
    if (!o) return;
    setValue(o.value);
    onValueChange?.(o.value);
    setOpen(false);
    button.current?.focus();
  };
  const openList = (at: number) => {
    setActive(at);
    setOpen(true);
  };

  const onButtonKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      openList(e.key === 'ArrowUp' ? options.length - 1 : selected);
    }
  };
  const onListKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      close('escape');
    } else if (e.key === 'Tab') {
      // Tab leaves the list: close it and let focus move on.
      setOpen(false);
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      choose(active);
    } else if (isListKey(e.key)) {
      e.preventDefault();
      setActive(moveIndex(e.key, active, options.length));
    }
  };

  return (
    <div className="xsel" ref={root} data-enhanced={enhanced ? 'true' : undefined}>
      <select
        id={id}
        name={name}
        value={value}
        tabIndex={enhanced ? -1 : undefined}
        aria-hidden={enhanced ? true : undefined}
        onChange={(e) => {
          setValue(e.target.value);
          onValueChange?.(e.target.value);
        }}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {enhanced ? (
        <>
          <button
            ref={button}
            type="button"
            className="xsel-b"
            aria-haspopup="listbox"
            aria-expanded={open}
            aria-controls={open ? listId : undefined}
            aria-label={`${label}: ${options[selected]?.label ?? ''}`}
            onClick={() => (open ? close('escape') : openList(selected))}
            onKeyDown={onButtonKey}
          >
            <span>{options[selected]?.label}</span>
            <Chevron />
          </button>
          {open ? (
            <div ref={list} id={listId} className="xsel-m" role="listbox" aria-label={label}>
              {options.map((o, i) => (
                <div
                  key={o.value}
                  role="option"
                  aria-selected={i === selected}
                  tabIndex={-1}
                  onClick={() => choose(i)}
                  onKeyDown={onListKey}
                  onMouseMove={() => active !== i && setActive(i)}
                >
                  <Tick />
                  <span>{o.label}</span>
                </div>
              ))}
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

/**
 * A pill segmented control for two or three choices: native radios under the labels, so it submits and
 * works with the keyboard everywhere. The thumb slides to the checked one in CSS.
 */
export function Segmented({
  name,
  label,
  options,
  defaultValue,
}: {
  name: string;
  label: string;
  options: Option[];
  defaultValue: string;
}) {
  const index = Math.max(
    0,
    options.findIndex((o) => o.value === defaultValue),
  );
  const [value, setValue] = useState(options[index]?.value ?? '');
  return (
    <fieldset
      className="seg"
      data-count={options.length}
      data-index={options.findIndex((o) => o.value === value)}
    >
      <legend className="label">{label}</legend>
      <div className="seg-track">
        <span className="seg-thumb" aria-hidden="true" />
        {options.map((o) => (
          <label key={o.value} className="seg-opt">
            <input
              type="radio"
              name={name}
              value={o.value}
              checked={value === o.value}
              onChange={() => setValue(o.value)}
            />
            <span>{o.label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/** A switch: a native checkbox drawn as a 44x26 track with a sliding knob. */
export function Switch({
  label,
  ...props
}: { label: string } & Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'>) {
  return (
    <label className="switch-row">
      <input type="checkbox" className="switch" {...props} />
      <span>{label}</span>
    </label>
  );
}
