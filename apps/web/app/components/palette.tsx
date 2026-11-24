// The quick-search palette: a dialog opened by Cmd/Ctrl+K or the key button in the top bar's search box.
import { useEffect, useId, useRef, useState } from 'react';
import { useFetcher, useLocation, useNavigate } from 'react-router';
import { isListKey, moveIndex, trapTarget } from '../lib/menu-nav';
import type { loader as quickLoader } from '../routes/quick';

const DEBOUNCE_MS = 180;

export function Palette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState('');
  const [active, setActive] = useState(-1);
  const fetcher = useFetcher<typeof quickLoader>();
  const navigate = useNavigate();
  const { pathname, search } = useLocation();
  const dialog = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const listId = useId();
  const term = q.trim();
  const hits = term && fetcher.data?.q === term ? fetcher.data.hits : [];

  // Remember what had focus, move it into the dialog, and give it back on close.
  useEffect(() => {
    if (!open) return;
    opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    input.current?.focus();
    return () => {
      opener.current?.focus();
      setQ('');
      setActive(-1);
    };
  }, [open]);

  // Navigation closes it.
  const here = `${pathname}${search}`;
  const first = useRef(here);
  useEffect(() => {
    if (first.current !== here) {
      first.current = here;
      if (open) onClose();
    }
  }, [here, open, onClose]);

  // Debounced lookup against the existing search API (through the /quick resource route).
  useEffect(() => {
    if (!open || !term) return;
    const t = setTimeout(() => fetcher.load(`/quick?q=${encodeURIComponent(term)}`), DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [open, term, fetcher.load]);

  if (!open) return null;

  const go = (to: string) => {
    onClose();
    navigate(to);
  };
  const submit = () => {
    const hit = hits[active];
    if (hit) go(`/e/${encodeURIComponent(hit.key)}`);
    else if (term) go(`/search?q=${encodeURIComponent(term)}`);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      submit();
    } else if (e.key === 'Tab') {
      const focusable = [...(dialog.current?.querySelectorAll<HTMLElement>('input, a[href], button') ?? [])];
      const next = trapTarget(focusable, document.activeElement as HTMLElement | null, e.shiftKey);
      if (next) {
        e.preventDefault();
        next.focus();
      }
    } else if (isListKey(e.key) && e.key !== 'Home' && e.key !== 'End') {
      e.preventDefault();
      setActive(moveIndex(e.key, active, hits.length));
    }
  };

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: the backdrop closes on a press; Escape does the same from the keyboard
    // biome-ignore lint/a11y/useKeyWithClickEvents: Escape is handled on the dialog
    <div
      className="ov"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={dialog}
        className="pal"
        role="dialog"
        aria-modal="true"
        aria-label="Quick search"
        onKeyDown={onKeyDown}
      >
        <div className="pin">
          <input
            ref={input}
            type="search"
            role="combobox"
            aria-expanded={hits.length > 0}
            aria-controls={listId}
            aria-activedescendant={active >= 0 ? `${listId}-${active}` : undefined}
            aria-label="Search the index"
            placeholder="Search a CVE, product, breach or term"
            maxLength={200}
            autoComplete="off"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setActive(-1);
            }}
          />
        </div>
        <div id={listId} role="listbox" aria-label="Matches">
          {hits.map((h, i) => (
            <div
              key={h.key}
              id={`${listId}-${i}`}
              role="option"
              tabIndex={-1}
              aria-selected={i === active}
              className={i === active ? 'sel' : undefined}
            >
              <a
                href={`/e/${encodeURIComponent(h.key)}`}
                tabIndex={-1}
                onClick={(e) => {
                  e.preventDefault();
                  go(`/e/${encodeURIComponent(h.key)}`);
                }}
              >
                <span className="mono muted">{h.key}</span>
                <span>{h.title}</span>
              </a>
            </div>
          ))}
        </div>
        <p className="ft muted" role="status">
          {term && hits.length === 0 && fetcher.state === 'idle' && fetcher.data?.q === term
            ? 'No quick matches. Enter searches everything.'
            : 'Arrow keys move, Enter opens, Esc closes.'}
        </p>
      </div>
    </div>
  );
}
