// The `account/do` action, free of the Workers runtime so it can be tested. Every request: the Origin header must
// equal the request origin (403), a session must exist (401), and the `intent` field picks one validated call.
import {
  MAX_DISPLAY_NAME_CHARS,
  MAX_SAVED_SEARCH_NAME_CHARS,
  type SavedSearchParams,
} from '@ti/core/account';
import {
  ApiBadRequest,
  ApiConflict,
  ApiRateLimited,
  ApiUnavailable,
  NotFound,
  SignInRequired,
} from '../data/api.server';
import type { AccountClient } from '../data/types';
import { DELETE_PHRASE } from './account-phrase';
import { parseSearchParams } from './search-params';

export { DELETE_PHRASE };
export const ENTRY_ID = /^[A-Za-z0-9._:-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type ActionResult =
  | { ok: true; intent: string; [key: string]: unknown }
  | { ok: false; error: string; status: number };

export interface ActionDeps {
  /** Null when signed out. */
  getClient: () => Promise<AccountClient | null>;
}

const hasControl = (s: string) => [...s].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127);
const fail = (status: number, error: string): ActionResult => ({ ok: false, error, status });

function name(raw: FormDataEntryValue | null, max: number): string | null {
  if (typeof raw !== 'string') return null;
  const v = raw.trim();
  return v.length >= 1 && v.length <= max && !hasControl(v) ? v : null;
}

/** The saved-search body for a `?q=…&type=…` string: the same validation the search page applies. */
export function savedSearchBody(
  qs: string,
  nameField: string,
): { name: string; query: string; params: SavedSearchParams } {
  const p = parseSearchParams(new URLSearchParams(qs.replace(/^\?/, '')));
  const params: SavedSearchParams = {};
  if (p.type) params.type = p.type;
  if (p.sig) params.sig = p.sig;
  if (p.sev) params.sev = [p.sev];
  if (p.year) params.year = [p.year];
  if (p.sort) params.sort = p.sort;
  const query = p.q ?? '';
  return { name: nameField || query || 'Saved search', query, params };
}

export async function handleAccountAction(request: Request, deps: ActionDeps): Promise<ActionResult> {
  if (request.method !== 'POST') return fail(405, 'method_not_allowed');
  if (request.headers.get('origin') !== new URL(request.url).origin) return fail(403, 'bad_origin');
  const client = await deps.getClient();
  if (!client) return fail(401, 'sign_in_required');
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return fail(400, 'bad_request');
  }
  const intent = form.get('intent');
  try {
    switch (intent) {
      case 'profile': {
        const displayRaw = form.get('displayName');
        const display = typeof displayRaw === 'string' ? displayRaw.trim() : '';
        if (display.length > MAX_DISPLAY_NAME_CHARS || hasControl(display))
          return fail(400, 'bad_display_name');
        const digest = form.get('digest');
        if (digest !== 'daily' && digest !== 'weekly' && digest !== 'off') return fail(400, 'bad_digest');
        const weekday = Number(form.get('digestWeekday'));
        if (!/^[0-6]$/.test(String(form.get('digestWeekday')))) return fail(400, 'bad_weekday');
        const me = await client.patchMe({
          displayName: display === '' ? null : display,
          alerts: { instant: form.get('instant') === 'on', digest, digestWeekday: weekday },
        });
        return { ok: true, intent, me };
      }
      case 'watch': {
        const id = form.get('id');
        if (typeof id !== 'string' || id.length > 100 || !ENTRY_ID.test(id)) return fail(400, 'bad_id');
        const item = await client.watch(id);
        return { ok: true, intent, entryKey: item.entryKey };
      }
      case 'unwatch': {
        const id = form.get('id');
        if (typeof id !== 'string' || id.length > 100 || !ENTRY_ID.test(id)) return fail(400, 'bad_id');
        await client.unwatch(id);
        return { ok: true, intent, entryKey: id };
      }
      case 'watch-alerts': {
        const id = form.get('id');
        const on = form.get('alertsOn');
        if (typeof id !== 'string' || id.length > 100 || !ENTRY_ID.test(id)) return fail(400, 'bad_id');
        if (on !== 'true' && on !== 'false') return fail(400, 'bad_alerts');
        const item = await client.watch(id, on === 'true');
        return { ok: true, intent, entryKey: item.entryKey, alertsOn: item.alertsOn };
      }
      case 'save-search': {
        const qs = form.get('qs');
        if (typeof qs !== 'string' || qs.length > 600) return fail(400, 'bad_query');
        const rawName = form.get('name');
        const given = rawName === null || rawName === '' ? '' : name(rawName, MAX_SAVED_SEARCH_NAME_CHARS);
        if (given === null) return fail(400, 'bad_name');
        const body = savedSearchBody(qs, given);
        const label = name(body.name.slice(0, MAX_SAVED_SEARCH_NAME_CHARS), MAX_SAVED_SEARCH_NAME_CHARS);
        if (label === null) return fail(400, 'bad_name');
        const saved = await client.saveSearch({ ...body, name: label });
        return { ok: true, intent, name: saved.name };
      }
      case 'delete-search': {
        const id = form.get('id');
        if (typeof id !== 'string' || !UUID.test(id)) return fail(400, 'bad_id');
        await client.deleteSearch(id);
        return { ok: true, intent };
      }
      case 'delete-account': {
        if (form.get('confirm') !== DELETE_PHRASE) return fail(400, 'confirmation_mismatch');
        await client.deleteAccount();
        return { ok: true, intent };
      }
      default:
        return fail(400, 'unknown_intent');
    }
  } catch (err) {
    if (err instanceof SignInRequired) return fail(401, 'sign_in_required');
    if (err instanceof ApiConflict) return fail(409, err.error);
    if (err instanceof ApiBadRequest) return fail(400, 'bad_request');
    if (err instanceof NotFound) return fail(404, 'not_found');
    if (err instanceof ApiRateLimited) return fail(429, 'rate_limited');
    if (err instanceof ApiUnavailable) {
      console.error(err.message, err.cause);
      return fail(
        502,
        intent === 'delete-account' && err.status === 502 ? 'delete_sign_in_failed' : 'unavailable',
      );
    }
    throw err;
  }
}
