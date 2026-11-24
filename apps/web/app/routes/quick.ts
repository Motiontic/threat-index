import { getData } from '../data/data.server';
import { MAX_QUERY } from '../lib/search-params';
import type { Route } from './+types/quick';

export interface QuickHit {
  key: string;
  title: string;
}

/** Up to 8 matches for the quick-search palette. A resource route: no page, no markup. */
export async function loader({ request }: Route.LoaderArgs): Promise<{ q: string; hits: QuickHit[] }> {
  const q = (new URL(request.url).searchParams.get('q') ?? '').trim().slice(0, MAX_QUERY);
  if (!q) return { q, hits: [] };
  try {
    const res = await getData(request).search({ q });
    return { q, hits: res.hits.slice(0, 8).map((h) => ({ key: h.key, title: h.title })) };
  } catch {
    return { q, hits: [] };
  }
}
