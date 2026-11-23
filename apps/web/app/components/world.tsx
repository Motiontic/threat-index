import { Form, Link } from 'react-router';
import type { WorldQuery } from '../data/types';
import { worldHref } from '../lib/world';

/** A GET search box for a world list. The filters ride along as hidden fields. */
export function WorldSearch({
  action,
  params,
  label,
}: {
  action: string;
  params: WorldQuery;
  label: string;
}) {
  return (
    <Form method="get" action={action} className="search-form" role="search" aria-label={label}>
      <input
        className="input"
        type="search"
        name="q"
        defaultValue={params.q ?? ''}
        maxLength={100}
        aria-label={label}
        placeholder={label}
      />
      {(params.kind ?? []).map((k) => (
        <input key={`kind-${k}`} type="hidden" name="kind" value={k} />
      ))}
      {(params.framework ?? []).map((f) => (
        <input key={`framework-${f}`} type="hidden" name="framework" value={f} />
      ))}
      <button type="submit" className="button button-primary">
        Search
      </button>
    </Form>
  );
}

export interface FilterChip {
  label: string;
  /** The filter values this chip selects; empty for "All". */
  values: string[];
}

/** Filter chips that are plain links; the active one is marked with `aria-current`. */
export function FilterChips({
  path,
  field,
  params,
  chips,
}: {
  path: string;
  field: 'kind' | 'framework';
  params: WorldQuery;
  chips: FilterChip[];
}) {
  const current = params[field] ?? [];
  return (
    <nav className="chips" aria-label="Filter">
      {chips.map((c) => {
        const active = c.values.length === current.length && c.values.every((v) => current.includes(v));
        return (
          <Link
            key={c.label}
            to={worldHref(path, {
              ...(params.q ? { q: params.q } : {}),
              ...(c.values.length ? { [field]: c.values } : {}),
            })}
            className={active ? 'chip chip-ok' : 'chip'}
            aria-current={active ? 'page' : undefined}
          >
            {c.label}
          </Link>
        );
      })}
    </nav>
  );
}

export function WorldPager({
  path,
  params,
  page,
  next,
}: {
  path: string;
  params: WorldQuery;
  page: number;
  next: number | null;
}) {
  if (page <= 1 && next === null) return null;
  return (
    <nav className="pager" aria-label="Pages">
      {page > 1 ? <Link to={worldHref(path, params)}>First page</Link> : null}
      {next !== null ? <Link to={worldHref(path, params, next)}>Next page</Link> : null}
    </nav>
  );
}
